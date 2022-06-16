import pytest
import requests_mock
from src import hikaxpro
from src.models import SessionLoginCap
from src.helpers import xmlBuilder
from src import consts

@pytest.fixture(scope="session")
def theaxpro():
    theaxpro = hikaxpro.HikAxPro("192.168.1.103", "blabla@blabla.com", "blablabla")
    return theaxpro

@requests_mock.Mocker(kw='mock')
def test_getSessionParams(theaxpro, **kwargs):        
    url = f"http://{theaxpro.host}{consts.Endpoints.Session_Capabilities}{theaxpro.username}"
    responseText = """<SessionLoginCap version="2.0" xmlns="http://www.hikvision.com/ver20/XMLSchema">
                            <sessionID>116c191b1981ca41fd110a4140e63c522c0d168a460fed22bc0b4ca84e18fe0e</sessionID>
                            <challenge>f0a902b12718652487db2b0cd9e83c4a</challenge><iterations>100</iterations>
                            <isSupportRTSPWithSession>true</isSupportRTSPWithSession>
                            <isIrreversible>true</isIrreversible>
                            <sessionIDVersion>2.1</sessionIDVersion>
                            <salt>22CF57B6ADE75214A4C87042B3272630C55EF5D782AB3BE4C9EC4DA1CD95AF3B</salt>
                            <salt2>7BEB8CA39D05B89CABC4003FDCBA5AE73556CB8008BCEE3CBCA48CABC3AC201B</salt2>
                        </SessionLoginCap>"""    

    kwargs["mock"].get(url, text=responseText, status_code=200)

    sessionCap = theaxpro.getSessionParams()
    assert sessionCap is not None

def test_parseSessionResponse(theaxpro):
    sessionXml = """<SessionLoginCap version="2.0" xmlns="http://www.hikvision.com/ver20/XMLSchema">
                        <sessionID>2109bea576cb68f1c2fc7de994efae250de4e2d75c0856762e97429f1f8bce17</sessionID>
                        <challenge>ab1c5d159387de8388b097709e8fecf9</challenge>
                        <iterations>100</iterations>
                        <isSupportRTSPWithSession>true</isSupportRTSPWithSession>
                        <isIrreversible>true</isIrreversible>
                        <sessionIDVersion>2.1</sessionIDVersion>
                        <salt>22CF57B6ADE75214A4C87042B3272630C55EF5D782AB3BE4C9EC4DA1CD95AF3B</salt>
                        <salt2>7BEB8CA39D05B89CABC4003FDCBA5AE73556CB8008BCEE3CBCA48CABC3AC201B</salt2>
                    </SessionLoginCap>"""
    
    axProSession = theaxpro.parseSessionResponse(sessionXml)
    
    assert len(axProSession.sessionID) > 0
    assert len(axProSession.challange) > 0
    assert len(axProSession.salt) > 0
    assert len(axProSession.salt2) > 0

def test_encodePassword_Irrevesible(theaxpro):
    sessionID = ''
    challange = '82360cd6ffd7beda4398cf67bfbd1ea9'
    iteration = 100
    salt = '22CF57B6ADE75214A4C87042B3272630C55EF5D782AB3BE4C9EC4DA1CD95AF3B'
    salt2 = '7BEB8CA39D05B89CABC4003FDCBA5AE73556CB8008BCEE3CBCA48CABC3AC201B'
    sessionCap = SessionLoginCap.SessionLoginCap(sessionID, challange, salt, salt2, True, iteration)    

    encodedPassword = theaxpro.encodePassword(sessionCap)

    assert encodedPassword == "777b95a40f8b5b9ca25101d3c73168adb340f2001b611a74104c34352962d647"

def test_encodePassword_Not_Irreversible(theaxpro):
    sessionID = ''
    challange = '82360cd6ffd7beda4398cf67bfbd1ea9'
    iteration = 100
    salt = '22CF57B6ADE75214A4C87042B3272630C55EF5D782AB3BE4C9EC4DA1CD95AF3B'
    salt2 = '7BEB8CA39D05B89CABC4003FDCBA5AE73556CB8008BCEE3CBCA48CABC3AC201B'
    sessionCap = SessionLoginCap.SessionLoginCap(sessionID, challange, salt, salt2, False, iteration)    

    encodedPassword = theaxpro.encodePassword(sessionCap)
    assert encodedPassword == "2b31a14ba59914a8e5e5510063e5d500ef322e76bc6c160df6a86b35c1e89ddd"

@requests_mock.Mocker(kw='mock')
def test_connect_successfull(theaxpro, **kwargs):  
    url = f"http://{theaxpro.host}{consts.Endpoints.Session_Capabilities}{theaxpro.username}"
    responseText = """<SessionLoginCap version="2.0" xmlns="http://www.hikvision.com/ver20/XMLSchema">
                            <sessionID>116c191b1981ca41fd110a4140e63c522c0d168a460fed22bc0b4ca84e18fe0e</sessionID>
                            <challenge>f0a902b12718652487db2b0cd9e83c4a</challenge><iterations>100</iterations>
                            <isSupportRTSPWithSession>true</isSupportRTSPWithSession>
                            <isIrreversible>true</isIrreversible>
                            <sessionIDVersion>2.1</sessionIDVersion>
                            <salt>22CF57B6ADE75214A4C87042B3272630C55EF5D782AB3BE4C9EC4DA1CD95AF3B</salt>
                            <salt2>7BEB8CA39D05B89CABC4003FDCBA5AE73556CB8008BCEE3CBCA48CABC3AC201B</salt2>
                        </SessionLoginCap>"""    

    kwargs["mock"].get(url, text=responseText, status_code=200)
    sessionLoginUrl = f"http://{theaxpro.host}{consts.Endpoints.Session_Login}" 
    kwargs["mock"].post(sessionLoginUrl, headers={"Set-Cookie": "blabla;bla"}, status_code=200)
    loginResult = theaxpro.connect()
    assert loginResult is True

def test_buildUrl_json(theaxpro):    
    url = theaxpro.buildUrl("http://blabla.com", True)
    assert url == "http://blabla.com?format=json"

def test_buildUrl_not_json(theaxpro):    
    url = theaxpro.buildUrl("http://blabla.com", False)
    assert url == "http://blabla.com"

@requests_mock.Mocker(kw='mock')
def test_arm_home(theaxpro, **kwargs):   
    url = f"http://{theaxpro.host}{consts.Endpoints.Alarm_ArmHome}"
    kwargs["mock"].put(url, status_code=200)
    result = theaxpro.arm_home()
    assert result is True

@requests_mock.Mocker(kw='mock')
def test_arm_away(theaxpro, **kwargs):    
    url = f"http://{theaxpro.host}{consts.Endpoints.Alarm_ArmAway}"
    kwargs["mock"].put(url, status_code=200)
    result = theaxpro.arm_away()
    assert result is True

@requests_mock.Mocker(kw='mock')
def test_disarm(theaxpro, **kwargs):    
    url = f"http://{theaxpro.host}{consts.Endpoints.Alarm_Disarm}"
    kwargs["mock"].put(url, status_code=200)
    result = theaxpro.disarm()
    assert result is True

@requests_mock.Mocker(kw='mock')
def test_subsystem_status(theaxpro, **kwargs):    
    url = f"http://{theaxpro.host}{consts.Endpoints.SubSystemStatus}"
    kwargs["mock"].get(url, status_code=200)
    result = theaxpro.subsystem_status()
    assert result is True

@requests_mock.Mocker(kw='mock')
def test_peripherals_status(theaxpro, **kwargs):    
    url = f"http://{theaxpro.host}{consts.Endpoints.PeripheralsStatus}"
    kwargs["mock"].get(url, status_code=200)
    result = theaxpro.periherals_status()
    assert result is True

@requests_mock.Mocker(kw='mock')
def test_zone_status(theaxpro, **kwargs):    
    url = f"http://{theaxpro.host}{consts.Endpoints.ZoneStatus}"
    kwargs["mock"].get(url, status_code=200)
    result = theaxpro.zone_status()
    assert result is True

@requests_mock.Mocker(kw='mock')
def test_bypass_zone(theaxpro, **kwargs):
    url = f"http://{theaxpro.host}{consts.Endpoints.BypassZone}1"
    kwargs["mock"].put(url, status_code=200)
    result = theaxpro.bypass_zone(1)
    assert result is True

@requests_mock.Mocker(kw='mock')
def test_recover_bypass_zone(theaxpro, **kwargs):
    url = f"http://{theaxpro.host}{consts.Endpoints.RecoverBypassZone}1"
    kwargs["mock"].put(url, status_code=200)
    result = theaxpro.recover_bypass_zone(1)
    assert result is True