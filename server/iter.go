package main

import (
	"zeroScannerGo/engine"
)

type TaskItem struct {
	PocName string        // poc名称
	PocType string        // 当前poc支持的target类型
	Service string        // 当前poc支持的协议
	Params  engine.Params // 扫描参数
}

type TargetIter struct {
	pocIterList  []*Iter
	targetList   []ParsedTarget
	pocIterIndex int
	targetIndex  int
	pocItem      []string
	next         func() []string
	Total        int
	IsEmpty      bool
}

func (ti *TargetIter) Init(pocIterList []*Iter, targetList []ParsedTarget) {
	ti.pocIterList = pocIterList
	ti.targetList = targetList
	if len(ti.pocIterList) > 0 && len(ti.targetList) > 0 {
		ti.next = ti.pocIterList[ti.pocIterIndex].NewNext()
		ti.pocIterIndex++
	}
	for _, pocIter := range ti.pocIterList {
		ti.Total += pocIter.Total * len(targetList)
	}
}

func (ti *TargetIter) Next() *TaskItem {
	if len(ti.pocIterList) == 0 || len(ti.targetList) == 0 {
		ti.IsEmpty = true
		return nil
	}

	if ti.targetIndex > len(ti.targetList)-1 {
		ti.targetIndex = 0
	}

	if ti.targetIndex == 0 {
		for {
			ti.pocItem = ti.next()
			if ti.pocItem == nil {
				if ti.pocIterIndex > len(ti.pocIterList)-1 {
					ti.IsEmpty = true
					return nil
				}
				ti.next = ti.pocIterList[ti.pocIterIndex].NewNext()
				ti.pocIterIndex++
			} else {
				break
			}
		}
	}

	target := ti.targetList[ti.targetIndex]
	ti.targetIndex++

	return &TaskItem{
		PocName: ti.pocItem[0],
		PocType: ti.pocItem[1],
		Service: ti.pocItem[2],
		Params: engine.Params{
			Method:       target.Method,
			Target:       target.Target,
			ParsedTarget: target.UrlObj,
			ContentType:  target.ContentType,
			Data:         target.Data,
			Username:     ti.pocItem[3],
			Password:     ti.pocItem[4],
			Other:        ti.pocItem[5],
		},
	}
}

type Iter struct {
	Total int
	lists [][]string
}

func (iter *Iter) Init(lists [][]string) {
	iter.Total = 1
	for _, list := range lists {
		iter.Total *= len(list)
	}
	iter.lists = lists
}

func (iter *Iter) NewNext() func() []string {
	x := 0
	return func() []string {
		if x >= iter.Total {
			return nil
		}
		step := iter.Total
		item := make([]string, len(iter.lists))
		for i, l := range iter.lists {
			step /= len(l)
			item[i] = l[x/step%len(l)]
		}
		x++
		return item
	}
}

func NewPocIter(pocName, pocType string, service, userDict, passDict, otherDict []string) *Iter {
	if len(userDict) == 0 {
		userDict = []string{""}
	}
	if len(passDict) == 0 {
		passDict = []string{""}
	}
	if len(otherDict) == 0 {
		otherDict = []string{""}
	}

	iter := &Iter{}
	iter.Init([][]string{[]string{pocName}, []string{pocType}, service, otherDict, passDict, userDict})
	return iter
}
