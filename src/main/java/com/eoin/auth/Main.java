package com.eoin.auth;

public class Main {
    public static void main(String[] args) throws Exception {
        AuthSystem auth = new AuthSystem();

        System.out.println("Registering user 'alice' with password 'password123'");
        boolean reg = auth.register("alice", "password123".toCharArray());
        System.out.println("Registered: " + reg);

        System.out.println("Attempting successful login for alice");
        String token = auth.login("alice", "password123".toCharArray());
        System.out.println("Login token: " + token);
        System.out.println("Is session valid? " + auth.isSessionValid(token));

        System.out.println("Attempting failed logins to trigger lockout");
        for (int i = 0; i < 6; i++) {
            String t = auth.login("alice", "wrongpass".toCharArray());
            System.out.println("Attempt " + (i+1) + ", token=" + t);
        }

        System.out.println("Attempt login with correct password after lockout");
        String t2 = auth.login("alice", "password123".toCharArray());
        System.out.println("Login token after lockout: " + t2);

        System.out.println("Attempt login for non-existent user 'bob'");
        String t3 = auth.login("bob", "any".toCharArray());
        System.out.println("Token for bob: " + t3);
    }
}
