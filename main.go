package main

import (
	"log"

	"github.com/casbin/casbin/v2"
)

func check(e *casbin.Enforcer, sub, obj, act string) {
	ok, _ := e.Enforce(sub, obj, act)
	if ok {
		log.Printf("%s Can %s %s\n", sub, act, obj)
	} else {
		log.Printf("%s Can not %s %s\n", sub, act, obj)
	}
}

func main() {
	e, err := casbin.NewEnforcer("./model.conf", "./policy.csv")
	if err != nil {
		log.Fatalf("NewEnforcer failed: %v\n", err)
	}

	// 权限检查
	log.Println("权限检查")
	check(e, "dajun", "data", "read")
	check(e, "1", "data", "read")
	check(e, "dajun", "1", "game")
	check(e, "1", "1", "game")
	check(e, "dajun", "data", "write")
	check(e, "lizi", "data", "read")
	check(e, "lizi", "data", "write")

	// 角色管理器
	log.Println("角色管理器")
	rm := e.GetRoleManager()
	// 获取角色的用户列表
	u, _ := rm.GetUsers("admin")
	log.Println("admin menbers: ", u)
	// 获取用户的角色列表
	r, _ := rm.GetRoles("abc")
	log.Println("abc groups: ", r)

	// 获取用户的角色列表
	g, _ := e.GetImplicitRolesForUser("abc")
	log.Println("abc groups: ", g)

	// 获取用户的所有权限
	p, _ := e.GetImplicitPermissionsForUser("abc")
	log.Println("abc permissions: ", p)
	for _, v := range p {
		log.Printf("group: %s, obj: %s, permission: %s\n", v[0], v[1], v[2])
	}

	// 添加用户角色关系
	userGroup := [][]string{
		{"an", "testGroup"},
		{"an", "admin"},
	}

	hasGroup, _ := e.GetImplicitRolesForUser("an")

	hasGroupRule := make([][]string, 0)
	for _, v := range hasGroup {
		hasGroupRule = append(hasGroupRule, []string{"an", v})
	}
	// 移除用户的组
	areRulesRemoved, _ := e.RemoveGroupingPolicies(hasGroupRule)
	log.Println("removed: ", areRulesRemoved)

	// 添加用户的组
	addGroupPolicy, _ := e.AddGroupingPolicies(userGroup)
	log.Println("addGroupPolicy: ", addGroupPolicy)

	// 移除用户与角色的关系
	removed, _ := e.RemoveGroupingPolicy("an", "testGroup")
	log.Println("remove : ", removed)

	// 角色权限管理示例
	groupPolicy := [][]string{
		{"testGroup", "data2", "read"},
		{"testGroup", "data3", "read"},
	}

	// 获取角色的所有权限
	// p 代表 police, 0 代表通过角色名过滤，改0为1，则代表通过权限名过滤，testGroup代表角色
	hasPolicies := e.GetFilteredNamedPolicy("p", 0, "testGroup")
	log.Println("testGroup policies: ", hasPolicies)
	// 删除权限
	removePolicies, _ := e.RemovePolicies(hasPolicies)
	log.Println("removePolicies: ", removePolicies)
	// 添加角色权限
	addedPolicy, _ := e.AddPolicies(groupPolicy)
	log.Println("addedPolicy: ", addedPolicy)

	// 获取用户的角色
	g2, _ := e.GetImplicitRolesForUser("an")
	log.Println("an groups: ", g2)
	// 获取用户的权限
	p2, _ := e.GetImplicitPermissionsForUser("an")
	log.Println("an permissions: ", p2)
	for _, v := range p2 {
		log.Printf("group: %s, obj: %s, permission: %s\n", v[0], v[1], v[2])
	}
	// 获取角色的权限
	gp := e.GetFilteredNamedPolicy("p", 0, "testGroup")
	log.Println("testGroup polices: ", gp)

	t := e.GetFilteredNamedPolicy("p", 2, "read")
	log.Println("t: ", t)
	// 保存权限到数据库
	err = e.SavePolicy()
	if err != nil {
		log.Printf("policy save failed, error: %v", err)
	}
}
