""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """
import json

from requests import request, exceptions as req_exceptions
from connectors.core.connector import get_logger, ConnectorError


logger = get_logger("symantec-management-center")


class Symantec:
    def __init__(self, config, *args, **kwargs):
        server_url = config.get("server_url")
        if not server_url.startswith('https://') and not server_url.startswith('http://'):
            server_url = "https://"+server_url
        self.url = server_url
        self.username = str(config.get("username"))
        self.password = str(config.get("password"))
        self.verify_ssl = config.get("verify_ssl")

    def api_request(self, method, endpoint, params={}, data={}):
        try:
            endpoint = self.url + endpoint
            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json"
            }
            logger.debug(f"\n-------------req start-------------\n{method} - {endpoint}\nparams: {params}\ndata: {data}\n")
            response = request(method, endpoint, headers=headers, auth=(self.username, self.password), params=params, data=json.dumps(data), verify=self.verify_ssl)

            if response.status_code in [200, 201, 204]:
                if response.text != "":
                    return response.json()
                else:
                    return True
            else:
                if response.text != "":
                    err_resp = response.json()
                    error_msg = 'Response [{0}:{1} Details: {2}]'.format(response.status_code, response.reason, err_resp)
                else:
                    error_msg = 'Response [{0}:{1}]'.format(response.status_code, response.reason)
                logger.error(error_msg)
                raise ConnectorError(error_msg)
        except req_exceptions.SSLError:
            logger.error('An SSL error occurred')
            raise ConnectorError('An SSL error occurred')
        except req_exceptions.ConnectionError:
            logger.error('A connection error occurred')
            raise ConnectorError('A connection error occurred')
        except req_exceptions.Timeout:
            logger.error('The request timed out')
            raise ConnectorError('The request timed out')
        except req_exceptions.RequestException:
            logger.error('There was an error while handling the request')
            raise ConnectorError('There was an error while handling the request')
        except Exception as err:
            raise ConnectorError(str(err))


def build_params(params):
    new_params = {}
    for key, value in params.items():
        if value is False or value == 0 or value:
            new_params[key] = value
    return new_params


def get_policies(config, params):
    ob = Symantec(config)
    params = build_params(params)
    return ob.api_request("GET", "/policies", params=params)


def get_policy_details(config, params):
    ob = Symantec(config)
    params = build_params(params)
    return ob.api_request("GET", f"/policies/{params['uuid']}")


def create_policy(config, params):
    ob = Symantec(config)
    params = build_params(params)
    return ob.api_request("POST", "/policies", data=params)


def update_policy(config, params):
    ob = Symantec(config)
    params = build_params(params)
    uuid = params.pop("uuid")
    return ob.api_request("PUT", f"/policies/{uuid}", data=params)


def delete_policy(config, params):
    ob = Symantec(config)
    params = build_params(params)
    uuid = params.pop("uuid")
    return ob.api_request("DELETE", f"/policies/{uuid}", data=params)


def add_policy_content(config, params):
    ob = Symantec(config)
    params = build_params(params)
    uuid = params.pop("uuid")
    return ob.api_request("POST", f"/policies/{uuid}/content", data=params)


def get_policy_content(config, params):
    ob = Symantec(config)
    params = build_params(params)
    uuid = params.pop("uuid")
    return ob.api_request("GET", f"/policies/{uuid}/content")


def get_policy_content_by_version(config, params):
    ob = Symantec(config)
    params = build_params(params)
    uuid = params.pop("uuid")
    version = params.pop("version")
    return ob.api_request("GET", f"/policies/{uuid}/content/{version}")


def check_health_ex(config):
    try:
        get_policies(config, {})
        return True
    except Exception as err:
        raise ConnectorError(str(err))


operations = {
    "get_policies": get_policies,
    "get_policy_details": get_policy_details,
    "create_policy": create_policy,
    "update_policy": update_policy,
    "delete_policy": delete_policy,
    "add_policy_content": add_policy_content,
    "get_policy_content": get_policy_content,
    "get_policy_content_by_version": get_policy_content_by_version
}

# update and delete remaining