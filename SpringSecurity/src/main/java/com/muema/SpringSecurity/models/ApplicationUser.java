package com.muema.SpringSecurity.models;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;

/**
 * Represents an application user with roles, implementing UserDetails for Spring Security.
 */
@Entity
@Table(name = "users") // Maps this class to the "users" table in the database
public class ApplicationUser implements UserDetails {

    // Getters and setters
    // Returns the user ID
    @Getter
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO) // Automatically generates a unique user ID
    private Integer userId;

    @Column(unique = true) // Ensures that usernames are unique in the database
    private String username;

    private String password;

    // Many-to-many relationship with Role entity
    @ManyToMany(fetch = FetchType.EAGER) // Loads roles eagerly
    @JoinTable(
            name = "user_role_junction", // Junction table to map users to roles
            joinColumns = @JoinColumn(name = "user_id"), // Foreign key in the junction table for user
            inverseJoinColumns = @JoinColumn(name = "role_id") // Foreign key for role in the junction table
    )
    private Set<Role> authorities; // Set of roles assigned to the user

    // Default constructor
    public ApplicationUser() {
        super();
        authorities = new HashSet<>(); // Initializes the authorities set
    }

    // Parameterized constructor
    public ApplicationUser(Integer userId, String username, String password, Set<Role> authorities) {
        super();
        this.userId = userId;
        this.username = username;
        this.password = password;
        this.authorities = authorities;
    }

    public void setUserId(Integer userId) {
        this.userId = userId; // Sets the user ID
    }

    public void setAuthorities(Set<Role> authorities) {
        this.authorities = authorities; // Sets the user's roles
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.authorities; // Returns the granted authorities (roles)
    }

    @Override
    public String getPassword() {
        return this.password; // Returns the user's password
    }

    public void setPassword(String password) {
        this.password = password; // Sets the user's password
    }

    @Override
    public String getUsername() {
        return this.username; // Returns the username
    }

    public void setUsername(String username) {
        this.username = username; // Sets the username
    }

    // Methods for account status checks (can be modified for more complex logic)
    @Override
    public boolean isAccountNonExpired() {
        return true; // Indicates if the account has expired
    }

    @Override
    public boolean isAccountNonLocked() {
        return true; // Indicates if the account is locked
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true; // Indicates if the credentials (password) have expired
    }

    @Override
    public boolean isEnabled() {
        return true; // Indicates if the account is enabled
    }
}
