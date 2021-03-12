package com.wjl.springsecuritydemo.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * @author wangJiaLun
 * @date 2021-03-12
 **/
@Data
@AllArgsConstructor
@NoArgsConstructor
public class Users {

    private Integer id;

    private String username;

    private String password;
}
