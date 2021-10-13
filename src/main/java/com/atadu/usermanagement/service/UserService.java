package com.atadu.usermanagement.service;

import com.atadu.usermanagement.domain.User;
import com.atadu.usermanagement.exception.domain.EmailNotFoundException;
import com.atadu.usermanagement.exception.domain.UserNotFoundException;
import com.atadu.usermanagement.exception.domain.UsernameExistException;
import org.springframework.web.multipart.MultipartFile;

import javax.mail.MessagingException;
import java.io.IOException;
import java.util.List;

public interface UserService {
    User register(String firstname, String lastName, String username, String email) throws UserNotFoundException, EmailNotFoundException, UsernameExistException, MessagingException;

    List<User> getUsers();

    User findUserByUsername(String username);

    User findUserByEmail(String email);

    User addNewUser(String firstName, String lastName, String username, String email, String role, boolean isNonLocked, boolean isActive, MultipartFile profileImage) throws UserNotFoundException, EmailNotFoundException, UsernameExistException, IOException;

    User updateUser(String currentUsername, String newFirstName, String newLastName, String newUsername, String newEmail, String newRole, boolean isNonLocked, boolean isActive, MultipartFile newProfileImage) throws UserNotFoundException, EmailNotFoundException, UsernameExistException, IOException;

    void deleteUser(long id);

    void resetPassword(String email) throws MessagingException, EmailNotFoundException;

    User updateProfileImage(String username, MultipartFile newImage) throws UserNotFoundException, EmailNotFoundException, UsernameExistException, IOException;
}
