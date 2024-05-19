package com.springsecurity.spr_security.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@CrossOrigin
public class HomeController {

    @ResponseBody
    @RequestMapping(value = {"/", "/home"} ,method = RequestMethod.GET)
    public Object home(){
        return "home";
    }

    @ResponseBody
    @RequestMapping(value = "/profile" ,method = RequestMethod.GET)
    public Object profile(){
        return "Welcome to Security PROFILE EVERYONE";
    }

//    @ResponseBody
//    @RequestMapping(value = "/login", method = RequestMethod.GET)
//    public Object login(){
//        return "login";
//    }

}
