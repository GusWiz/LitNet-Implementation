import pytest
from Litsune import Litsune

def test_update_anomList_new_entry():
    L = Litsune()
    L.currentSrc = "10.0.0.1"
    L.anomList = {}

    L.update_anomList()

    assert "10.0.0.1" in L.anomList
    assert L.anomList["10.0.0.1"] == 1

def test_update_anomList_existing_entry():
    L = Litsune()
    L.currentSrc = "10.0.0.1"
    L.anomList = {"10.0.0.1": 1}

    L.update_anomList()

    assert L.anomList["10.0.0.1"] == 2