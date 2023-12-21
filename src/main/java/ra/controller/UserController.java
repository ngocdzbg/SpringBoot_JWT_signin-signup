package ra.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import ra.jwt.JwtTokenProvider;
import ra.model.entity.ERole;
import ra.model.entity.Roles;
import ra.model.entity.Users;
import ra.model.service.RoleService;
import ra.model.service.UserService;
import ra.payload.request.LoginRequest;
import ra.payload.request.SignUpRequest;
import ra.payload.response.JwtResponse;
import ra.payload.response.MessageResponse;
import ra.sercurity.CustomUserDetails;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@CrossOrigin("*")
@RestController
@RequestMapping(value = "/api/v1/auth")
public class UserController {
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private JwtTokenProvider jwtTokenProvider;
    @Autowired
    private UserService userService;
    @Autowired
    private RoleService roleService;
    @Autowired
    private PasswordEncoder passwordEncoder;

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@RequestBody SignUpRequest signUpRequest) {
        if (userService.existsByUserName(signUpRequest.getUserName())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Username is already exist."));
        }
        if (userService.existsByEmail(signUpRequest.getEmail())) {
            return ResponseEntity.badRequest().body(new MessageResponse("Error: Email is already exist."));
        }
        Users user = new Users();
        user.setUserName(signUpRequest.getUserName());
        user.setPassword(passwordEncoder.encode(signUpRequest.getPassword()));
        user.setEmail(signUpRequest.getEmail());
        user.setPhone(signUpRequest.getPhone());
        user.setUserStatus(true);
        SimpleDateFormat sdf = new SimpleDateFormat("dd/MM/yyyy");
        Date dateNow = new Date();
        String strNow = sdf.format(dateNow);
        try {
            user.setCreated(sdf.parse(strNow));
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        Set<String> strRoles = signUpRequest.getListRoles();
        Set<Roles> listRoles = new HashSet<>();
        if (strRoles == null) {
            //Set cho User quyen mac dinh
            Roles userRole = roleService.findByRoleName(ERole.ROLE_USER).orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            listRoles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Roles adminRole = roleService.findByRoleName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found"));
                        listRoles.add(adminRole);
                    case "moderator":
                        Roles moderatorRole = roleService.findByRoleName(ERole.ROLE_MODERATOR)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found"));
                        listRoles.add(moderatorRole);
                    case "user":
                        Roles userRole = roleService.findByRoleName(ERole.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found"));
                        listRoles.add(userRole);
                }
            });
        }
        user.setListRoles(listRoles);
        userService.saveOrUpdate(user);
        return ResponseEntity.ok(new MessageResponse("User registered successfully."));
    }

    @PostMapping("/signin")
    public ResponseEntity<?> loginUser(@RequestBody LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUserName(), loginRequest.getPassword())
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
        CustomUserDetails customUserDetail = (CustomUserDetails) authentication.getPrincipal();
        //Sinh Jwt tra ve client
        String jwt = jwtTokenProvider.generateToken(customUserDetail);
        //lay cac quyen cua User
        List<String> listRoles = customUserDetail.getAuthorities().stream()
                .map(item -> item.getAuthority()).collect(Collectors.toList());
        return ResponseEntity.ok(
                new JwtResponse(jwt, customUserDetail.getUsername(), customUserDetail.getEmail(), customUserDetail.getPhone(),
                listRoles));
    }
}
