from typing import Optional

import requests
import xml.etree.ElementTree as ET
import consts
from models import SessionLoginCap,SessionLogin
from helpers import sha256, xmlBuilder
from errors import errors
from datetime import datetime


class HikAxPro:
    """HikVisison Ax Pro Alarm panel coordinator."""
    def __init__(self, host, username, password):        
        self.host = host
        self.username = username
        self.password = password
        self.cookie = ''

    def getSessionParams(self):
        sessionResponse = requests.get(f"http://{self.host}{consts.Endpoints.Session_Capabilities}{self.username}")                            
        if sessionResponse.status_code == 200:
            try:
                sessionCap = self.parseSessionResponse(sessionResponse.text)
                return sessionCap
            except:
                raise errors.IncorrectResponseContentError()
        else:
            return None
        
    def parseSessionResponse(self, xmlData):
        root = ET.fromstring(xmlData)
        namespaces = {'xmlns': consts.XML_SCHEMA}
        sessionCap = SessionLoginCap.SessionLoginCap(
            root.find("xmlns:sessionID", namespaces).text,
            root.find("xmlns:challenge", namespaces).text,
            root.find("xmlns:salt", namespaces).text,
            root.find("xmlns:salt2", namespaces).text,
            root.find("xmlns:isIrreversible", namespaces).text,
            int(root.find("xmlns:iterations", namespaces).text)
        )
        return sessionCap

    def encodePassword(self, sessionCap):
        result = ''
        if sessionCap.isIrreversible:
            result = sha256.sha256(f"{self.username}{sessionCap.salt}{self.password}")
            result = sha256.sha256(f"{self.username}{sessionCap.salt2}{result}")
            result = sha256.sha256(f"{result}{sessionCap.challange}")

            for i in range(2, sessionCap.iteration):
                result = sha256.sha256(result)
        else:
            result = f"{sha256.sha256(self.password)}{sessionCap.challange}"

            for i in range(1, sessionCap.iteration):
                result = sha256.sha256(result)
        
        return result

    def connect(self):
        params = self.getSessionParams()

        encodedPassword = self.encodePassword(params)

        sessionXml = xmlBuilder.serializeObject(
            SessionLogin.SessionLogin(
                params.sessionID,
                self.username,
                encodedPassword                                
            )
        )

        dt = datetime.now()
        timestamp = datetime.timestamp(dt)                
        sessionLoginUrl = f"http://{self.host}{consts.Endpoints.Session_Login}?timeStamp={int(timestamp)}"
        result = False
        try:
            loginResponse = requests.post(sessionLoginUrl, sessionXml)

            if loginResponse.status_code == 200:
                self.cookie = loginResponse.headers["Set-Cookie"].split(";")[0]
                result = True
        except:
            result = False
        
        return result

    def buildUrl(self, endpoint, isJson):
        paramPrefix = "&" if "?" in endpoint else "?"
        return (f"{endpoint}{paramPrefix}format=json" if isJson else endpoint)

    def arm_home(self, sub_id: Optional[int]):
        sid = "0xffffffff" if sub_id is None else str(sub_id)
        armEnpoint = self.buildUrl(f"http://{self.host}{consts.Endpoints.Alarm_ArmHome.replace('{}', sid)}", True)
        response = self.makeRequest(armEnpoint, consts.Method.PUT)

        if response.status_code != 200:
            raise errors.UnexpectedResponseCodeError(response.status_code, response.text)

        return response.status_code == 200

    def arm_away(self, sub_id: Optional[int]):
        sid = "0xffffffff" if sub_id is None else str(sub_id)
        armEnpoint = self.buildUrl(f"http://{self.host}{consts.Endpoints.Alarm_ArmAway.replace('{}', sid)}", True)
        response = self.makeRequest(armEnpoint, consts.Method.PUT)

        if response.status_code != 200:
            raise errors.UnexpectedResponseCodeError(response.status_code, response.text)

        return response.status_code == 200

    def disarm(self, sub_id: Optional[int]):
        sid = "0xffffffff" if sub_id is None else str(sub_id)
        disarmEndpoint = self.buildUrl(f"http://{self.host}{consts.Endpoints.Alarm_Disarm.replace('{}', sid)}", True)
        response = self.makeRequest(disarmEndpoint, consts.Method.PUT)

        if response.status_code != 200:
            raise errors.UnexpectedResponseCodeError(response.status_code, response.text)

        return response.status_code == 200

    def subsystem_status(self):
        statusEndpoint = f"http://{self.host}{consts.Endpoints.SubSystemStatus}"
        statusEndpoint = self.buildUrl(statusEndpoint, True)
        response = self.makeRequest(statusEndpoint, consts.Method.GET)

        if response.status_code != 200:
            raise errors.UnexpectedResponseCodeError(response.status_code, response.text)

        return response.json()

    def periherals_status(self):
        peripheralsEndpoint = f"http://{self.host}{consts.Endpoints.PeripheralsStatus}"
        peripheralsEndpoint = self.buildUrl(peripheralsEndpoint, True)
        response = self.makeRequest(peripheralsEndpoint, consts.Method.GET)

        if response.status_code != 200:
            raise errors.UnexpectedResponseCodeError(response.status_code, response.text)

        return response.json()

    def zone_status(self):
        zoneStatus = f"http://{self.host}{consts.Endpoints.ZoneStatus}"
        zoneStatus = self.buildUrl(zoneStatus, True)
        response = self.makeRequest(zoneStatus, consts.Method.GET)
    
        if response.status_code != 200:
            raise errors.UnexpectedResponseCodeError(response.status_code, response.text)

        return response.json()

    def bypass_zone(self, zone_id):
        bypassZoneEndpoint = f"http://{self.host}{consts.Endpoints.BypassZone}{zone_id}"
        bypassZoneEndpoint = self.buildUrl(bypassZoneEndpoint, True)
        response = self.makeRequest(bypassZoneEndpoint, consts.Method.PUT)

        if response.status_code != 200:
            raise errors.UnexpectedResponseCodeError(response.status_code, response.text)

        return response.status_code == 200

    def recover_bypass_zone(self, zone_id):
        recoverBypassZoneEndpoint = f"http://{self.host}{consts.Endpoints.RecoverBypassZone}{zone_id}"
        recoverBypassZoneEndpoint = self.buildUrl(recoverBypassZoneEndpoint, True)
        response = self.makeRequest(recoverBypassZoneEndpoint, consts.Method.PUT)

        return response.status_code == 200

    def get_interface_mac_address(self, interface_id):
        interfacesEndpoint = f"http://{self.host}{consts.Endpoints.InterfaceInfo}"

        response = self.makeRequest(interfacesEndpoint, consts.Method.GET)

        if response.status_code == 200:
            return xmlBuilder.get_mac_address_of_interface(response.text, interface_id)

        return ''

    def get_area_arm_status(self, area_id):
        armStatusEndpoint = f"http://{self.host}{consts.Endpoints.AreaArmStatus}"
        armStatusEndpoint = self.buildUrl(armStatusEndpoint, True)
        
        data = {"SubSysList": [{"SubSys": {"id": area_id}}]}

        response = self.makeRequest(armStatusEndpoint, consts.Method.POST, data = data, isJson = True)

        try:
            if response.status_code == 200:
                responseJson = response.json()
                return responseJson["ArmStatusList"][0]["ArmStatus"]["status"]
        except:
            return ''

        return ''

        

    def makeRequest(self, endpoint, method, data=None, isJson = False):
        headers = {"Cookie": self.cookie}        

        if method == consts.Method.GET:
            response = requests.get(endpoint, headers=headers)
        elif method == consts.Method.POST:
            if isJson:
                response = requests.post(endpoint, json = data, headers=headers)
            else:
                response = requests.post(endpoint, data=data, headers=headers)
        elif method == consts.Method.PUT:
            if isJson:
                response = requests.post(endpoint, json=data, headers=headers)
            else:
                response = requests.put(endpoint, data=data, headers=headers)
        else: return None
            
        if response.status_code == 401:
            self.connect()
            response = self.makeRequest(endpoint, method, data, isJson)

        return response
    




            