package com.thtf.common;

/**
 * ========================
 * 系统常量
 * Created with IntelliJ IDEA.
 * User：pyy
 * Date：2019/6/10
 * Time：10:32
 * Version: v1.0
 * ========================
 */
public interface Constants {
    String UN_DELETED = "0";//未删除
    String DELETED = "1";   //已删除

    String UP = "1";    //上移
    String DOWN = "2";  //下移
    String TOP = "3";   //置顶
    String BOTTOM = "4";//置底

    String ENABLE = "1";    //启用
    String DISABLE = "0";   //停用

    String AUTH_LEVEL_BASE = "1";//基础校验
    String AUTH_LEVEL_STRICT = "2";//严格校验

    String IMAGE_TYPE_THEME = "theme";//主题图片
    String IMAGE_TYPE_APP = "app";//app图片

    String THEME_DEFAULT = "1";//默认主题
    String THEME_NO_DEFAULT = "0";//非默认主题

    String PROFILE_DEV = "dev";//开发环境
    String PROFILE_TEST = "test";//测试环境
    String PROFILE_PROD = "prod";//生产环境

    String IS_ADMIN = "1";//管理员
    String NO_ADMIN = "0";//非管理员

    String BUSINESSCODE_SET_ADMIN = "管理员管理业务";

    String DICT_TYPE_FIXED = "1";//定长
    String DICT_TYPE_UNFIXED = "2";//不定长

    String LOCK = "1";//锁定
    String UN_LOCK = "0";//解锁

    String IS_PART_TIME = "是";
    String NOT_PART_TIME = "否";
}
