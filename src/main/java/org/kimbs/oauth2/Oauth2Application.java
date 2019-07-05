package org.kimbs.oauth2;

import org.kimbs.oauth2.model.Account;
import org.kimbs.oauth2.service.AccountService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import javax.security.auth.login.AccountException;
import java.util.Arrays;

@SpringBootApplication
public class Oauth2Application {

    public static void main(String[] args) {
        SpringApplication.run(Oauth2Application.class, args);
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    CommandLineRunner init(AccountService accountService) {
        return (event) -> Arrays.asList("kimbs,parkcs,yangjo,kimsg,parkjy,leeys,leetg,choimg".split(",")).forEach(
                username -> {
                    Account account = new Account();
                    account.setUsername(username);
                    account.setPassword("password");
                    account.setName(username);
                    account.grantAuthority("ROLE_USER");
                    if (username.equals("kimbs")) {
                        account.grantAuthority("ROLE_ADMIN");
                    }

                    try {
                        accountService.register(account);
                    } catch (AccountException e) {
                        e.printStackTrace();
                    }
                }
        );
    }
}
