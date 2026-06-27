from enum import Enum

from app.logger import soar_logger


# ==========================================================
# Available Roles
# ==========================================================

class Role(str, Enum):
    ADMIN = "admin"
    SENIOR_ANALYST = "senior_analyst"
    ANALYST = "analyst"


# ==========================================================
# Permissions
# ==========================================================

ROLE_PERMISSIONS = {
    Role.ADMIN: [
        "view_alerts",
        "view_dashboard",
        "view_cases",
        "execute_playbook",
        "approve_high_impact",
        "block_ip",
        "isolate_host",
    ],

    Role.SENIOR_ANALYST: [
        "view_alerts",
        "view_dashboard",
        "view_cases",
        "execute_playbook",
        "approve_high_impact",
    ],

    Role.ANALYST: [
        "view_alerts",
        "view_dashboard",
        "view_cases",
    ],
}


# ==========================================================
# High Impact Actions
# ==========================================================

HIGH_IMPACT_ACTIONS = [
    "block_ip",
    "isolate_host",
    "approve_high_impact",
]


# ==========================================================
# Mock Users Database
# ==========================================================

USERS = {
    "admin_user": {
        "username": "admin_user",
        "role": Role.ADMIN,
        "full_name": "System Administrator",
    },

    "senior_analyst": {
        "username": "senior_analyst",
        "role": Role.SENIOR_ANALYST,
        "full_name": "Senior SOC Analyst",
    },

    "analyst_user": {
        "username": "analyst_user",
        "role": Role.ANALYST,
        "full_name": "SOC Analyst",
    },
}


# ==========================================================
# User Functions
# ==========================================================

def get_user(username: str) -> dict | None:
    """
    Get user details.
    """
    return USERS.get(username)


def get_role(username: str) -> Role | None:
    """
    Return user's role.
    """
    user = get_user(username)

    if not user:
        soar_logger.warning(
            f"User not found | Username: {username}"
        )
        return None

    return user["role"]


# ==========================================================
# Permission Checks
# ==========================================================

def has_permission(username: str, permission: str) -> bool:
    """
    Check whether a user has a permission.
    """
    role = get_role(username)

    if role is None:
        return False

    allowed = permission in ROLE_PERMISSIONS.get(role, [])

    soar_logger.info(
        f"Permission Check | "
        f"User={username} | "
        f"Role={role.value} | "
        f"Permission={permission} | "
        f"Allowed={allowed}"
    )

    return allowed


def can_execute_playbook(username: str) -> bool:
    """
    Check whether user can execute playbooks.
    """
    return has_permission(
        username,
        "execute_playbook"
    )


def can_approve_high_impact(username: str) -> bool:
    """
    Only Admin and Senior Analyst
    can approve high-impact playbooks.
    """
    result = has_permission(
        username,
        "approve_high_impact"
    )

    soar_logger.info(
        f"High Impact Approval | "
        f"User={username} | "
        f"Allowed={result}"
    )

    return result


def is_admin(username: str) -> bool:
    """
    Check if user is an administrator.
    """
    return get_role(username) == Role.ADMIN


def is_senior_analyst(username: str) -> bool:
    """
    Check if user is a senior analyst.
    """
    return get_role(username) == Role.SENIOR_ANALYST


def can_execute_high_impact(username: str) -> bool:
    """
    High impact actions can be executed
    only by Admin or Senior Analyst.
    """
    role = get_role(username)

    return role in (
        Role.ADMIN,
        Role.SENIOR_ANALYST,
    )


# ==========================================================
# Utility Functions
# ==========================================================

def get_all_users() -> list:
    """
    Return all users.
    """
    return [
        {
            "username": user["username"],
            "full_name": user["full_name"],
            "role": user["role"].value,
        }
        for user in USERS.values()
    ]


def get_available_roles() -> list:
    """
    Return all available roles.
    """
    return [role.value for role in Role]