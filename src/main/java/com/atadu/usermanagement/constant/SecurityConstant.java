package com.atadu.usermanagement.constant;

public class SecurityConstant {
    public static final long EXPIRATION_TIME = 432_000_000;
    public static final String TOKEN_HEADER = "Bearer ";
    public static final String JWT_TOKEN_HEADER = "Jwt-Token";
    public static final String TOKEN_CANNOT_BE_VERIFIED = "Token can not be verified";
    public static final String GET_ARRAYS_LLC = "Get Arrays, LLC";
    public static final String GET_ARRAYS_ADMINISTRATION = "User Management Portal";
    public static final String AUTHORITIES = "Authorities";
    public static final String FORBIDDEN_MESSAGE = "You need to log in to access this page";
    public static final String ACCESS_DENIED_MESSAGE = "You don't have permission to access this page";
    public static final String OPTION_HTTP_METHOD = "OPTIONS";
    public static final String[] PUBLIC_URLS = {"/user/login", "/user/register", "/user/image/**"};
    //public static final String[] PUBLIC_URLS = {"**"};
}
