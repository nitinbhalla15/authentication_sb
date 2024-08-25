package com.project.AuthenticationLayer.repo;

import com.project.AuthenticationLayer.entity.UserRegisterDetails;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserRepository extends JpaRepository<UserRegisterDetails, UUID> {

    @Query(nativeQuery = true,value = "Select * from user_details where email_id = :subject")
    Optional<UserRegisterDetails> findUserBySubject(String subject);

}
