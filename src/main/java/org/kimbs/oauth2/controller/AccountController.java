package org.kimbs.oauth2.controller;

import org.kimbs.oauth2.model.Account;
import org.kimbs.oauth2.service.AccountService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import javax.security.auth.login.AccountException;

@RestController
public class AccountController {

    private final AccountService accountService;

    public AccountController(AccountService accountService) {
        this.accountService = accountService;
    }

    @GetMapping("/api/hello")
    public ResponseEntity<?> hello() {
        String name = SecurityContextHolder.getContext().getAuthentication().getName();
        String message = String.format("Hello %s", name);

        return new ResponseEntity<Object>(message, HttpStatus.OK);
    }

    @GetMapping("/api/me")
    public ResponseEntity<Account> me() {
        String username = SecurityContextHolder.getContext().getAuthentication().getName();

        return new ResponseEntity<>(accountService.findAccountByUsername(username), HttpStatus.OK);
    }

    @PostMapping("/api/account")
    public ResponseEntity<?> register(@RequestBody final Account account) throws AccountException {
        account.grantAuthority("ROLE_USER");
        return new ResponseEntity<Object>(accountService.register(account), HttpStatus.CREATED);
    }

    @PreAuthorize("hasRole('USER')")
    @DeleteMapping(path = "/api/user/remove", produces = "application/json")
    public ResponseEntity<?> removeUser() {
        accountService.removeAuthenticatedAccount();
        return new ResponseEntity<>(HttpStatus.OK);
    }
}
