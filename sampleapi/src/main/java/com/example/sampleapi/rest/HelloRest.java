package com.example.sampleapi.rest;

import com.example.sampleapi.utils.JWEDecryptor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;


@RestController
public class HelloRest {

    JWEDecryptor decryptor = new JWEDecryptor();

    @GetMapping("/echo-jwe")
    String helloWorld (@RequestHeader("X-JWT-Assertion") String jwe) {
        try {
            if(jwe != null && !jwe.isEmpty()) {
                String claimSet = decryptor.getClaimSet(jwe);
                return claimSet;
            } else {
                return "No-X-JWT-Assertion";
            }
        } catch (Exception e) {
            return e.getMessage();
        }
    }

}
