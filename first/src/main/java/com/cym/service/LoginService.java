package com.cym.service;

import com.cym.dto.R;
import jakarta.servlet.http.HttpServletRequest;

/**
 * @author 79878
 * @version 1.0
 * Create by 2024/12/13 18:20
 */

public interface LoginService {
    R<Object> login(String username, String password, HttpServletRequest request);
}
