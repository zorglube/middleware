#!/usr/bin/env python3

import pytest
import sys
import os
import json
apifolder = os.getcwd()
sys.path.append(apifolder)
from functions import PUT, POST, GET, SSH_TEST, wait_on_job
from auto_config import ip, hostname, password, user
from pytest_dependency import depends

try:
    from config import AD_DOMAIN, ADPASSWORD, ADUSERNAME, ADNameServer
except ImportError:
    Reason = 'ADNameServer AD_DOMAIN, ADPASSWORD, or/and ADUSERNAME are missing in config.py"'
    pytestmark = pytest.mark.skip(reason=Reason)
else:
    from auto_config import dev_test
    # comment pytestmark for development testing with --dev-test
    pytestmark = pytest.mark.skipif(dev_test, reason='Skip for testing')


@pytest.mark.dependency(name="GOT_DNS")
def test_01_get_nameserver1_and_nameserver2():
    global nameserver1
    results = GET("/network/configuration/")
    assert results.status_code == 200, results.text
    nameserver1 = results.json()['nameserver1']


@pytest.mark.dependency(name="SET_DNS")
def test_02_set_nameserver_for_ad(request):
    depends(request, ["GOT_DNS"])
    global payload
    payload = {
        "nameserver1": ADNameServer,
    }
    global results
    results = PUT("/network/configuration/", payload)
    assert results.status_code == 200, results.text
    assert isinstance(results.json(), dict), results.text


@pytest.mark.dependency(name="AD_LDAP_ENABLED")
def test_03_enabling_activedirectory(request):
    depends(request, ["SET_DNS"])
    payload = {
        "bindpw": ADPASSWORD,
        "bindname": ADUSERNAME,
        "domainname": AD_DOMAIN,
        "netbiosname": hostname,
        "dns_timeout": 15,
        "verbose_logging": True,
        "enable": True
    }
    results = PUT("/activedirectory/", payload)
    assert results.status_code == 200, results.text
    job_id = results.json()['job_id']
    job_status = wait_on_job(job_id, 180)
    assert job_status['state'] == 'SUCCESS', str(job_status['results'])


@pytest.mark.dependency(name="AD_LDAP_IS_HEALTHY")
def test_04_get_activedirectory_state(request):
    depends(request, ["AD_LDAP_ENABLED"])
    results = GET('/activedirectory/started/')
    assert results.status_code == 200, results.text


def test_06_system_keytab_verify(request):
    """
    kerberos_principal_choices lists unique keytab principals in
    the system keytab. AD_MACHINE_ACCOUNT should add more than
    one principal.
    """
    global kerberos_principal
    depends(request, ["AD_LDAP_IS_HEALTHY", "ssh_password"], scope="session")
    cmd = 'midclt call kerberos.keytab.kerberos_principal_choices'
    results = SSH_TEST(cmd, user, password, ip)
    assert results['result'] is True, results['output']
    kerberos_principal = json.loads(results['output'])[0]

    cmd = 'midclt call kerberos._klist_test'
    results = SSH_TEST(cmd, user, password, ip)
    assert results['output'].strip() == 'True'


@pytest.mark.dependency(name="AD_LDAP_HAS_DOMAIN_INFO")
def test_07_get_domain_info(request):
    depends(request, ["AD_LDAP_IS_HEALTHY", "ssh_password"], scope="session")
    global ad_ldap_domain_info
    results = POST("/activedirectory/domain_info/", AD_DOMAIN)
    assert results.status_code == 200, results.text
    ad_ldap_domain_info = results.json()

    results = PUT("/activedirectory/", {"enable": False})
    assert results.status_code == 200, results.text
    job_id = results.json()['job_id']
    job_status = wait_on_job(job_id, 180)
    assert job_status['state'] == 'SUCCESS', str(job_status['results'])


@pytest.mark.dependency(name="SET_UP_AD_VIA_LDAP")
def test_08_setup_and_enabling_ldap(request):
    depends(request, ["AD_LDAP_HAS_DOMAIN_INFO", "ssh_password"], scope="session")
    results = GET("/kerberos/realm/")
    assert results.status_code == 200, results.text
    ad_realm_id = results.json()[0]['id']

    payload = {
        "basedn": ad_ldap_domain_info['Bind Path'],
        "binddn": '',
        "bindpw": '',
        "hostname": [AD_DOMAIN],
        "has_samba_schema": False,
        "ssl": "OFF",
        "kerberos_realm": ad_realm_id,
        "kerberos_principal": kerberos_principal,
        "enable": True
    }
    results = PUT("/ldap/", payload)
    assert results.status_code == 200, results.text
    job_id = results.json()['job_id']
    job_status = wait_on_job(job_id, 180)
    assert job_status['state'] == 'SUCCESS', str(job_status['results'])


"""
def test_09_check_kerberos_ldap(request):
    depends(request, ["SET_UP_AD_VIA_LDAP", "ssh_password"], scope="session")

    cmd = "midclt call kerberos.stop"
    results = SSH_TEST(cmd, user, password, ip)
    assert results['result'] is True, results['output']

    cmd = "midclt call kerberos.start"
    results = SSH_TEST(cmd, user, password, ip)
    assert results['result'] is True, results['output']

    cmd = 'midclt call kerberos._klist_test'
    results = SSH_TEST(cmd, user, password, ip)
    assert results['output'].strip() == 'True'


def test_10_verify_ldap_users(request):
    depends(request, ["SET_UP_AD_VIA_LDAP", "ssh_password"], scope="session")

    results = GET('/user', payload={
        'query-filters': [['local', '=', False]],
        'query-options': {'extra': {"search_dscache": True}},
    })
    assert results.status_code == 200, results.text
    assert len(results.json()) > 0, results.text

    results = GET('/group', payload={
        'query-filters': [['local', '=', False]],
        'query-options': {'extra': {"search_dscache": True}},
    })
    assert results.status_code == 200, results.text
    assert len(results.json()) > 0, results.text


@pytest.mark.dependency(name="RESTARTED_AD_AFTER_LDAP")
def test_20_restart_ad_before_leave(request):
    depends(request, ["SET_UP_AD_VIA_LDAP", "ssh_password"], scope="session")
    payload = {
        "basedn": '',
        "binddn": '',
        "bindpw": '',
        "hostname": [],
        "has_samba_schema": False,
        "ssl": "OFF",
        "kerberos_realm": None,
        "kerberos_principal": "",
        "auxiliary_parameters": "",
        "enable": False
    }
    results = PUT("/ldap/", payload)
    assert results.status_code == 200, results.text

    job_id = results.json()['job_id']
    job_status = wait_on_job(job_id, 180)
    assert job_status['state'] == 'SUCCESS', str(job_status['results'])

    results = PUT("/activedirectory/", {"enable": True})
    assert results.status_code == 200, results.text
    job_id = results.json()['job_id']
    job_status = wait_on_job(job_id, 180)
    assert job_status['state'] == 'SUCCESS', str(job_status['results'])


def test_21_leave_activedirectory(request):
    depends(request, ["RESTARTED_AD_AFTER_LDAP"])
    global payload, results
    payload = {
        "username": ADUSERNAME,
        "password": ADPASSWORD
    }
    results = POST("/activedirectory/leave/", payload)
    assert results.status_code == 200, results.text


def test_22_reset_dns(request):
    depends(request, ["SET_DNS"])
    global payload
    payload = {
        "nameserver1": nameserver1,
    }
    global results
    results = PUT("/network/configuration/", payload)
    assert results.status_code == 200, results.text
"""
