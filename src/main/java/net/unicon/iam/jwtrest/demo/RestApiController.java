package net.unicon.iam.jwtrest.demo;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

@RestController
public class RestApiController {

    @GetMapping("/data")
    public String someData(HttpServletRequest request) {
        return "Hello from REST API service protected by JWT";
    }
}
