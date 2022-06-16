import pytest
from src.helpers import xmlBuilder
from src.models import SessionLogin


def test_serializeObject():
    sessionLogin = SessionLogin.SessionLogin("1", "blabla@bla.com", "blapass")

    serializedSession = xmlBuilder.serializeObject(sessionLogin)

    assert serializedSession == "<SessionLogin><sessionID>1</sessionID><password>blapass</password><userName>blabla@bla.com</userName><sessionIDVersion>2.1</sessionIDVersion></SessionLogin>"