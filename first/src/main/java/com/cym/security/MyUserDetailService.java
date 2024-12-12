package com.cym.security;

import com.cym.dao.UserMapper;
import com.cym.pojo.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * @author 79878
 * @version 1.0
 * Create by 2024/12/10 13:50
 */

@Service
@Transactional
public class MyUserDetailService implements UserDetailsService {

    @Autowired
    private UserMapper userMapper;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userMapper.getUserByUsername(username);

        if (user == null) {
            throw new UsernameNotFoundException("用户不存在");
        }
        System.out.println("userId = " + user.getUserId());
        List<UserRole> userRoles = userMapper.getRoleIdByUserId(user.getUserId());
        List<String> permission = new ArrayList<>();
        List<String> roleNames = new ArrayList<>();
        if (userRoles != null) {
            List<Long> roleIdList = userRoles.stream().map(UserRole::getRoleId).collect(Collectors.toList());

            List<Role> roles = userMapper.getRolesByRoleIds(roleIdList);
            if (roles != null) {
                for (Role role : roles) {
                    roleNames.add("Role_" + role.getRoleName());
                }
            }

            List<RolePermission> permissionsByRoleIds = userMapper.getPermissionsByRoleIds(roleIdList);
            if (permissionsByRoleIds != null) {
                List<Long> permissionIdList = permissionsByRoleIds.stream().map(RolePermission::getPermissionId).toList();
                List<Permission> permissions = userMapper.getPermissionsByIds(permissionIdList);
                if (permissions != null) {
                    for (Permission p : permissions) {
                        permission.add(p.getPermissionName());
                    }
                }
            }
        }

        return new MyUserDetails(permission, roleNames, user);
    }
}
