package com.example.SpringSecurity_JWT.Repositories;

import com.example.SpringSecurity_JWT.User;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepository extends CrudRepository<User, Long> {
    User findByUsername(String username);
}
