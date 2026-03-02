const ROLE_PERMISSIONS = {
    admin: [
        'manage_users',
        'delete_records',
        'view_salary',
        'manage_salary',
        'manage_leaves',
        'manage_assets',
        'manage_notices',
        'view_analytics'
    ],
    hr: [
        'manage_users',
        'manage_leaves',
        'manage_notices'
    ],
    finance: [
        'view_salary',
        'manage_salary'
    ],
    it_admin: [
        'manage_assets',
        'delete_records'
    ],
    employee: []
};

const getPermissionsForRole = (role) => {
    return ROLE_PERMISSIONS[role] || [];
};

module.exports = { ROLE_PERMISSIONS, getPermissionsForRole };
