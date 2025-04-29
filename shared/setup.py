import os

def get_role() -> str:
    """
    Returns the role of the current machine.
    This function is used to determine if the process is a master or worker.
    """
    role = os.getenv("ROLE")
    if role is None:
        raise ValueError("Environment variable 'ROLE' is not set.")
    return role.lower()
