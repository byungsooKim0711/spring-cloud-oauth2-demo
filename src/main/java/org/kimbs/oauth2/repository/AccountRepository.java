package org.kimbs.oauth2.repository;

import org.kimbs.oauth2.model.Account;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AccountRepository extends JpaRepository<Account, Long> {

    Optional<Account> findByUsername(String username);

    Integer countByUsername(String username);
}
