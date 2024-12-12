package com.cym.dao;

import com.cym.pojo.*;

import java.util.List;

/**
 * @author 79878
 * @version 1.0
 * Create by 2024/12/10 13:46
 */

public interface UserMapper {
    User getUserByUsername(String username);
    List<UserRole> getRoleIdByUserId(Long userId);
    List<Role> getRolesByRoleIds(List<Long> roleIds);
    List<RolePermission> getPermissionsByRoleIds(List<Long> roleIds);
    List<Permission> getPermissionsByIds(List<Long> permissionIds);
}
