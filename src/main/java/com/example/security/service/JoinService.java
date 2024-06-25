package com.example.security.service;

import com.example.security.dto.JoinDto;
import com.example.security.entity.UserEntity;
import com.example.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class JoinService {


    private final UserRepository userRepository;

    private PasswordEncoder passwordEncoder;


    public void joinProcess(JoinDto joinDto) {


        //db에 이미 동일한 username을 가진 회원이 존재하는지?


        UserEntity data = new UserEntity();

        data.setUsername(joinDto.getUsername());
        data.setPassword(passwordEncoder.encode(joinDto.getPassword()));
        data.setRole("ROLE_USER");


        userRepository.save(data);
    }
}
