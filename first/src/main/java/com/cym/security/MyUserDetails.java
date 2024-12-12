package com.cym.security;

import com.cym.pojo.User;
import lombok.AllArgsConstructor;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.CollectionUtils;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

/**
 * @author 79878
 * @version 1.0
 * Create by 2024/12/12 14:39
 */
@Data
@AllArgsConstructor
public class MyUserDetails implements UserDetails {
    private List<String> permissions;
    private List<String> roleNames;
    private User user;

    public MyUserDetails(String username, String password) {
        User user = new User();
        user.setUsername(username);
        user.setPassword(password);
        this.user = user;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        List<GrantedAuthority> authorities = new ArrayList<>();
        if (!CollectionUtils.isEmpty(permissions)) {
            for (String permission : permissions) {
                authorities.add(new SimpleGrantedAuthority(permission));
            }
        }
        if (!CollectionUtils.isEmpty(roleNames)) {
            for (String roleName : roleNames) {
                authorities.add(new SimpleGrantedAuthority(roleName));
            }
        }
        return authorities;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return UserDetails.super.isAccountNonExpired();
    }

    @Override
    public boolean isAccountNonLocked() {
        return UserDetails.super.isAccountNonLocked();
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return UserDetails.super.isCredentialsNonExpired();
    }

    @Override
    public boolean isEnabled() {
        return UserDetails.super.isEnabled();
    }
}
