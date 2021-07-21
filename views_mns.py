# pylint: disable=E0611,E0401,E1101
"""
Renders Views to all DICE templates
"""
import logging
import ast
from django.views.generic.base import View
from django.http import JsonResponse
from django.shortcuts import render
from hub.util.sidebar_utilities import add_parameters
from django.contrib.auth.decorators import permission_required
from django.utils.decorators import method_decorator
from django.core.exceptions import ObjectDoesNotExist
from dice.models import Market, Device, Service, DeviceConfig, Miscellaneous, Tag
from dice.utils.config_generator import ConfigGenerator
from dice.utils.helper import get_all_configs, get_all_variables, save_all_configs, save_all_variables, \
    add_or_delete_mds, copy_defaults, save_landing_page_help
from dice.dice_mns.granite_integrator import GraniteIntegrator
from dice.dice_mns.managed_automator import ManagedAutomator


LOGGER = logging.getLogger('')

# DICE Tag is used to differentiate between DICE Instances
# Main DICE = fiber
# SMB DICE = coax
# MNS DICE = managed
# Voice DICE = voice
try:
    (TAG, Tag_is_created) = Tag.objects.get_or_create(name='managed')
except Exception as e:
    LOGGER.error("Unable to Get or Create Tag Object. Error: {}".format(e))
    TAG = None


def fill_footer_parameters(context_dict, request, title=''):
    """
    Method adds all parameters that are necessary for the page to render with the side and top bars. Can populate
    the sidebar with default data or customized menus, etc
    :param context_dict:
    :param request:
    :param title:
    :return:
    """
    context_dict["current_user"] = request.user

    return add_parameters("dice", "D I C E" + title, context_dict, request)


def create_template_dict(page):
    """
    Creates a new template dictionary, populates it with values common to all Views and returns the loaded template dict
    :param page: string - designates which page is being loaded
    :return: template_dict
    """
    template_dict = {}
    markets = Market.objects.filter(tag=TAG).order_by('name')
    services = Service.objects.filter(tag=TAG).order_by('name')

    if page == 'home':
        device_configs = DeviceConfig.objects.all()

        device_ids = []
        for device_config in device_configs:
            device_ids.append(device_config.device_id)

        devices = Device.objects.filter(id__in=device_ids, tag=TAG).order_by('name')

        try:
            landing_page_help = Miscellaneous.objects.get(identifier='landing_page_help', tag=TAG).content
        except ObjectDoesNotExist:
            landing_page_help = ''

        template_dict = {
            "markets": markets,
            "devices": devices,
            "services": services,
            "landing_page_help": landing_page_help,
        }

    elif page == 'config_manager':
        devices = Device.objects.filter(tag=TAG).order_by('name')

        template_dict = {
            "markets": markets,
            "devices": devices,
            "services": services,
        }

    return template_dict


class DiceMNSView(View):
    """
    Processes GET and POST requests from DICE Home page
    """
    template_name = 'dice.html'
    friendly_app_name = "DICE"

    @method_decorator(permission_required('dice.dice_mns_home', login_url='unauthorized_page'))
    def dispatch(self, *args, **kwargs):
        return super(DiceMNSView, self).dispatch(*args, **kwargs)

    def get(self, request):
        """
        Processes GET requests from DICE Home page
        :param request:
        :return:
        """
        try:
            values_dict = dict(request.GET)
            identifier = values_dict['identifier'][0]
        except KeyError:
            identifier = ''

        if identifier == 'config_data':
            variables, field_defaults, choices = get_all_variables('home', TAG)

            return JsonResponse({
                'variables': variables,
                'field_defaults': field_defaults,
                'choices': choices
            })

        template_dict = create_template_dict('home')

        LOGGER.info("DICE home page GET request by %s has been successfully processed.", request.user)
        return render(request, self.template_name, fill_footer_parameters(template_dict, request, ' | M N S'))

    def post(self, request):
        """
        Processes POST requests from DICE Home page
        :param request:
        :return:
        """
        values_dict = dict(request.POST)

        try:
            identifier = values_dict['identifier'][0]
        except KeyError:
            identifier = ''

        if identifier == 'granite_query':
            circuit_id = ast.literal_eval(values_dict['circuit_id'][0])

            granite_data = GraniteIntegrator(circuit_id, TAG).initiate()

            LOGGER.info("DICE MNS Home page POST request to query Granite by %s "
                        "has been successfully processed", request.user)
            return JsonResponse({'granite_data': granite_data})

        elif identifier == 'save_help_text':
            landing_page_help = ast.literal_eval(values_dict['landing_page_help'][0])

            save_landing_page_help(landing_page_help, TAG)

            LOGGER.info("DICE MNS Home page POST request to save Landing Page Help Text by %s "
                        "has been successfully processed.", request.user)
            return JsonResponse({'landing_page_help': landing_page_help})

        elif identifier == 'circuit_selection':
            circuit_id = ast.literal_eval(values_dict['circuit_id'][0])
            circuit_type = ast.literal_eval(values_dict['circuit_type'][0])

            LOGGER.info(f"DICE MNS - User {request.user} has selected Circuit '{circuit_type}' "
                        f"for Circuit ID: {circuit_id}")

            return JsonResponse({'circuit_selection_logged': True})

        elif identifier == 'automate_config':
            mns_auto = ManagedAutomator(
                ipAddress=ast.literal_eval(values_dict['ipAddress'][0]),
                vendor=ast.literal_eval(values_dict['vendor'][0]),
                model=ast.literal_eval(values_dict['model'][0]),
                fqdn=ast.literal_eval(values_dict['fqdn'][0]),
                config=values_dict['config'][0]
            )

            LOGGER.info(f"DICE MNS - User {request.user} has initiated automation of managed service.")

            response = mns_auto.automate()

            LOGGER.info(
                "DICE MNS - automation response for " \
                f"{mns_auto.payload.get('ipAddress')} / {mns_auto.payload.get('fqdn')}: {response.status_code}"
                )   

            if response.status_code >= 400:        
                return JsonResponse(response.json(), status=response.status_code)
            else:
                return JsonResponse({'resource_id': mns_auto.resource_id}, status=200)

        elif identifier == 'check_status':
            resource_id = values_dict['resource_id'][0]
            response = ManagedAutomator.check_status(resource_id)

            LOGGER.info(f"DICE MNS - User {request.user} checking status of {resource_id}. response: {response.status_code}")

            if response.status_code >= 400:     
                return JsonResponse(response.json(), status=response.status_code)

            response = response.json()
            return JsonResponse({
                'orchState': response['orchState'],
                'reason': response.get('reason')
                })

        final_config = ConfigGenerator(values_dict, TAG).final_config

        LOGGER.info("DICE home page POST request by %s has been successfully processed.", request.user)
        return JsonResponse({'final_config': final_config})


class ConfigManagerMNSView(View):
    """
    Processes GET and POST requests from DICE Config Manager page
    :return:
    """
    template_name = 'config_manager.html'

    @method_decorator(permission_required('dice.dice_mns_config_manager', login_url='unauthorized_page'))
    def dispatch(self, *args, **kwargs):
        return super(ConfigManagerMNSView, self).dispatch(*args, **kwargs)

    def get(self, request):
        """
        Processes GET requests from DICE Config Manager page
        :param request:
        :return:
        """
        try:
            values_dict = dict(request.GET)
            identifier = values_dict['identifier'][0]
        except KeyError:
            identifier = ''

        if identifier == 'config_data':
            configs = get_all_configs(TAG)
            variables, field_defaults, choices = get_all_variables('config_manager', TAG)

            return JsonResponse({
                'configs': configs,
                'variables': variables,
                'field_defaults': field_defaults,
                'choices': choices
            })

        template_dict = create_template_dict('config_manager')

        LOGGER.info("DICE Config Manager GET request by %s has been successfully processed.", request.user)
        return render(request, self.template_name, fill_footer_parameters(template_dict, request,
                                                                          ' - Config Manager | M N S'))

    def post(self, request):
        """
        Processes POST requests from DICE Config Manager page
        :param request:
        :return:
        """
        values_dict = dict(request.POST)

        template_dict = create_template_dict('config_manager')

        identifier = values_dict['identifier'][0]

        if identifier == 'config_upload':
            save_all_configs(values_dict, str(request.user), TAG)

        elif identifier == 'config_management':
            save_all_variables(values_dict, TAG)

        elif identifier == 'editor':
            add_or_delete_mds(values_dict, TAG)

        elif identifier == 'copy_defaults':
            copy_defaults(values_dict, TAG)

        LOGGER.info("DICE Config Manager POST request by %s has been successfully processed.", request.user)
        return render(request, self.template_name, fill_footer_parameters(template_dict, request,
                                                                          ' - Config Manager | M N S'))


class MNSAutomationView(View):
    template_name = 'mns_automation.html'

    def get(self, request):
        return render(request, self.template_name)