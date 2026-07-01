from app.rbac import (
    Role,
    get_user,
    get_role,
    has_permission,
    can_approve_high_impact,
    can_execute_playbook,
    can_execute_high_impact,
    is_admin,
    is_senior_analyst,
    get_all_users,
    get_available_roles,
)


# ==========================================================
# get_user tests
# ==========================================================

def test_get_user_admin_exists():
    user = get_user("admin_user")
    assert user is not None


def test_get_user_analyst_exists():
    user = get_user("analyst_user")
    assert user is not None


def test_get_user_senior_analyst_exists():
    user = get_user("senior_analyst")
    assert user is not None


def test_get_user_invalid_returns_none():
    user = get_user("unknown_user")
    assert user is None


# ==========================================================
# get_role tests
# ==========================================================

def test_get_role_admin():
    role = get_role("admin_user")
    assert role == Role.ADMIN


def test_get_role_analyst():
    role = get_role("analyst_user")
    assert role == Role.ANALYST


def test_get_role_senior_analyst():
    role = get_role("senior_analyst")
    assert role == Role.SENIOR_ANALYST


def test_get_role_invalid_user():
    role = get_role("unknown_user")
    assert role is None


# ==========================================================
# has_permission tests
# ==========================================================

def test_admin_has_all_permissions():
    assert has_permission("admin_user", "view_alerts") is True
    assert has_permission("admin_user", "block_ip") is True
    assert has_permission("admin_user", "isolate_host") is True
    assert has_permission("admin_user", "approve_high_impact") is True


def test_analyst_has_limited_permissions():
    assert has_permission("analyst_user", "view_alerts") is True
    assert has_permission("analyst_user", "view_cases") is True
    assert has_permission("analyst_user", "block_ip") is False
    assert has_permission("analyst_user", "isolate_host") is False


def test_senior_analyst_can_approve_high_impact():
    assert has_permission("senior_analyst", "approve_high_impact") is True


def test_invalid_user_has_no_permissions():
    assert has_permission("unknown_user", "view_alerts") is False


# ==========================================================
# can_approve_high_impact tests
# ==========================================================

def test_admin_can_approve_high_impact():
    assert can_approve_high_impact("admin_user") is True


def test_senior_analyst_can_approve():
    assert can_approve_high_impact("senior_analyst") is True


def test_analyst_cannot_approve_high_impact():
    assert can_approve_high_impact("analyst_user") is False


def test_invalid_user_cannot_approve():
    assert can_approve_high_impact("unknown_user") is False


# ==========================================================
# can_execute_playbook tests
# ==========================================================

def test_admin_can_execute_playbook():
    assert can_execute_playbook("admin_user") is True


def test_senior_analyst_can_execute_playbook():
    assert can_execute_playbook("senior_analyst") is True


def test_analyst_cannot_execute_playbook():
    assert can_execute_playbook("analyst_user") is False


# ==========================================================
# can_execute_high_impact tests
# ==========================================================

def test_admin_can_execute_high_impact():
    assert can_execute_high_impact("admin_user") is True


def test_senior_analyst_can_execute_high_impact():
    assert can_execute_high_impact("senior_analyst") is True


def test_analyst_cannot_execute_high_impact():
    assert can_execute_high_impact("analyst_user") is False


# ==========================================================
# is_admin tests
# ==========================================================

def test_is_admin_true():
    assert is_admin("admin_user") is True


def test_is_admin_false():
    assert is_admin("analyst_user") is False


# ==========================================================
# is_senior_analyst tests
# ==========================================================

def test_is_senior_analyst_true():
    assert is_senior_analyst("senior_analyst") is True


def test_is_senior_analyst_false():
    assert is_senior_analyst("analyst_user") is False


# ==========================================================
# get_all_users tests
# ==========================================================

def test_get_all_users_returns_list():
    users = get_all_users()
    assert isinstance(users, list)


def test_get_all_users_count():
    users = get_all_users()
    assert len(users) >= 3


def test_get_all_users_has_required_keys():
    users = get_all_users()
    for user in users:
        assert "username" in user
        assert "full_name" in user
        assert "role" in user


# ==========================================================
# get_available_roles tests
# ==========================================================

def test_get_available_roles_returns_list():
    roles = get_available_roles()
    assert isinstance(roles, list)


def test_get_available_roles_count():
    roles = get_available_roles()
    assert len(roles) >= 3


def test_get_available_roles_contains_admin():
    roles = get_available_roles()
    assert "admin" in roles


def test_get_available_roles_contains_analyst():
    roles = get_available_roles()
    assert "analyst" in roles


def test_get_available_roles_contains_senior_analyst():
    roles = get_available_roles()
    assert "senior_analyst" in roles