import pytest

from middlewared.test.integration.assets.roles import common_checks


@pytest.mark.parametrize("role", ["SHARING_READ", "SHARING_FTP_READ"])
def test_read_role_can_read(unprivileged_user_fixture, role):
    common_checks(unprivileged_user_fixture, "ftp.config", role, True, valid_role_exception=False)


@pytest.mark.parametrize("role", ["SHARING_READ", "SHARING_FTP_READ"])
def test_read_role_cant_write(unprivileged_user_fixture, role):
    common_checks(unprivileged_user_fixture, "ftp.update", role, False)


@pytest.mark.parametrize("role", ["SHARING_WRITE", "SHARING_FTP_WRITE"])
def test_write_role_can_write(unprivileged_user_fixture, role):
    common_checks(unprivileged_user_fixture, "ftp.update", role, True)
    common_checks(
        unprivileged_user_fixture, "service.control", role, True, method_args=["START", "ftp"],
        method_kwargs=dict(job=True), valid_role_exception=False,
    )
    common_checks(
        unprivileged_user_fixture, "service.control", role, True, method_args=["RESTART", "ftp"],
        method_kwargs=dict(job=True), valid_role_exception=False,
    )
    common_checks(
        unprivileged_user_fixture, "service.control", role, True, method_args=["RELOAD", "ftp"],
        method_kwargs=dict(job=True), valid_role_exception=False,
    )
    common_checks(
        unprivileged_user_fixture, "service.control", role, True, method_args=["STOP", "ftp"],
        method_kwargs=dict(job=True), valid_role_exception=False,
    )
