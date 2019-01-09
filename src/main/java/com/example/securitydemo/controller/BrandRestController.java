package com.example.securitydemo.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class BrandRestController {
    public static String version = "1.0.0";

    @RequestMapping(value = "/version" , method = {RequestMethod.POST,RequestMethod.GET})
    public String version(){
        return "Running version "+version;
    }

    @RequestMapping(value = "/greeting" , method = {RequestMethod.POST,RequestMethod.GET})
    public String hello(@RequestParam(value = "name",defaultValue = "world") String name ){
        return "Hello "+name+" !";
    }
}
