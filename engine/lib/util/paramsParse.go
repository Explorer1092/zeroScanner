package util

import (
	"errors"
	"net/url"
	"regexp"

	"github.com/golang-collections/collections/stack"
)

const (
	MODEAPPEND                      = 0 //默认是追加模式
	MODEREPLACE                     = 1 //替换模式
	STATE_EMPTY                 int = iota
	STATE_WAIT_FIRST_MAP_KEY
	STATE_WAIT_EACH_ARRAY_VALUE
	STATE_MAP_KEY_QUOTE_OPEN
	STATE_WAIT_MAP_COLON
	STATE_WAIT_MAP_VALUE
	STATE_WAIT_NEXT_MAP_KEY
	STATE_WAIT_NEXT_ARRAY_INFO
)

func getParaStrValues(para string) ([][]int, error) {
	words := ([]rune)(para)
	allResult := [][]int{}
	mapResult := [][]int{}
	jsonArrStack := stack.New()
	jsonArrStack.Push(STATE_EMPTY)
	err := errors.New("not json value")
	stateStack := stack.New()
	stateStack.Push(STATE_EMPTY)
	start := -1
	end := -1
	firstIntoEmpty := false
	for i := 0; i < len(words); i++ {
		switch stateStack.Peek().(int) {
		case STATE_EMPTY:
			switch words[i] {
			case '{':
				if firstIntoEmpty == false {
					firstIntoEmpty = true
				} else {
					return nil, err
				}
				stateStack.Push(STATE_WAIT_FIRST_MAP_KEY)
			case '[':
				if firstIntoEmpty == false {
					firstIntoEmpty = true
				} else {
					return nil, err
				}
				stateStack.Push(STATE_WAIT_EACH_ARRAY_VALUE)
			case '\r', ' ', '\n', '\t':
				continue
			default:
				return nil, err
			}
		case STATE_WAIT_FIRST_MAP_KEY:
			for {
				if words[i] == ' ' || words[i] == '\n' || words[i] == '\t' || words[i] == '\r' {
					if i+1 < len(words) {
						i = i + 1
					} else {
						return nil, err
					}
				} else {
					break
				}
			}
			switch words[i] {
			case '"':
				stateStack.Push(STATE_MAP_KEY_QUOTE_OPEN)
			case '}':
				stateStack.Pop()
			case '\r', ' ', '\n', '\t':
				continue
			default:
				return nil, err
			}
		case STATE_MAP_KEY_QUOTE_OPEN:
			for {
				if words[i] == '"' {
					stateStack.Pop()
					stateStack.Push(STATE_WAIT_MAP_COLON)
					break
				} else if words[i] == '\\' {
					if i+1 < len(words) {
						i = i + 1
					} else {
						return nil, err
					}
				}
				//走到这就是map key的组成部分
				if i+1 < len(words) {
					i = i + 1
				} else {
					return nil, err
				}
			}
		case STATE_WAIT_MAP_COLON:
			for {
				if words[i] == ':' {
					stateStack.Pop()
					stateStack.Push(STATE_WAIT_MAP_VALUE)
					break
				} else if words[i] == ' ' || words[i] == '\n' || words[i] == '\t' || words[i] == '\r' {
					if i+1 < len(words) {
						i = i + 1
					} else {
						return nil, err
					}
				} else {
					return nil, err
				}
			}
		case STATE_WAIT_MAP_VALUE:
			for {
				if words[i] == ' ' || words[i] == '\n' || words[i] == '\t' || words[i] == '\r' {
					if i+1 < len(words) {
						i = i + 1
					} else {
						return nil, err
					}
				} else {
					break
				}
			}
			switch {
			case words[i] == '"':
				start = i + 1
				for {
					if i+1 < len(words) {
						i = i + 1
					} else {
						return nil, err
					}
					if words[i] == '"' {
						stateStack.Pop()
						stateStack.Push(STATE_WAIT_NEXT_MAP_KEY)
						end = i
						switch jsonArrStack.Peek().(type) {
						case [][]int:
							//还在array中
							tmpValue := jsonArrStack.Pop()
							tmpValue = append(tmpValue.([][]int), []int{start, end})
							jsonArrStack.Push(tmpValue)
						default:
							//找到了一个map value，放入数组中
							mapResult = append(mapResult, []int{start, end})
						}
						break
					} else if words[i] == '\\' {
						if i+1 < len(words) {
							i = i + 1
						} else {
							return nil, err
						}
					}
				}
			case words[i] == 't':
				if i+3 < len(words) {
					if words[i+1] == 'r' && words[i+2] == 'u' && words[i+3] == 'e' {
						stateStack.Pop()
						stateStack.Push(STATE_WAIT_NEXT_MAP_KEY)
						i = i + 3
					}
				} else {
					return nil, err
				}
			case words[i] == 'n':
				if i+3 < len(words) {
					if words[i+1] == 'u' && words[i+2] == 'l' && words[i+3] == 'l' {
						stateStack.Pop()
						stateStack.Push(STATE_WAIT_NEXT_MAP_KEY)
						i = i + 3
					}
				} else {
					return nil, err
				}
			case words[i] == 'f':
				if i+4 < len(words) {
					if words[i+1] == 'a' && words[i+2] == 'l' && words[i+3] == 's' && words[i+4] == 'e' {
						stateStack.Pop()
						stateStack.Push(STATE_WAIT_NEXT_MAP_KEY)
						i = i + 4
					}
				} else {
					return nil, err
				}
			case (words[i] >= '0' && words[i] <= '9') || words[i] == '.':
				for {
					if i+1 < len(words) {
						i = i + 1
					} else {
						return nil, err
					}
					if (words[i] >= '0' && words[i] <= '9') || words[i] == '.' {
						continue
					} else {
						i = i - 1
						stateStack.Pop()
						stateStack.Push(STATE_WAIT_NEXT_MAP_KEY)
						break
					}
				}
			case words[i] == '{':
				stateStack.Pop()
				stateStack.Push(STATE_WAIT_NEXT_MAP_KEY)
				stateStack.Push(STATE_WAIT_FIRST_MAP_KEY)
			case words[i] == '[':
				stateStack.Pop()
				stateStack.Push(STATE_WAIT_NEXT_MAP_KEY)
				stateStack.Push(STATE_WAIT_EACH_ARRAY_VALUE)
			default:
				return nil, err
			}

		case STATE_WAIT_NEXT_MAP_KEY:
			for {
				if words[i] == ',' {
					stateStack.Pop()
					break
				} else if words[i] == '}' {
					stateStack.Pop()
					if !(stateStack.Peek().(int) == STATE_WAIT_NEXT_ARRAY_INFO || stateStack.Peek().(int) == STATE_WAIT_NEXT_MAP_KEY) {
						stateStack.Pop()
					}
					break
				} else if words[i] == ' ' || words[i] == '\n' || words[i] == '\t' || words[i] == '\r' {
					if i+1 < len(words) {
						i = i + 1
					} else {
						return nil, err
					}
				} else {
					return nil, err
				}
			}
		case STATE_WAIT_EACH_ARRAY_VALUE:
			eachArrResult := [][]int{}
			jsonArrStack.Push(eachArrResult)
			for {
				if words[i] == ' ' || words[i] == '\n' || words[i] == '\t' || words[i] == '\r' {
					if i+1 < len(words) {
						i = i + 1
					} else {
						return nil, err
					}
				} else {
					break
				}
			}
			switch {
			case words[i] == '"':
				start = i + 1
				for {
					if i+1 < len(words) {
						i = i + 1
					} else {
						return nil, err
					}
					if words[i] == '"' {
						stateStack.Pop()
						stateStack.Push(STATE_WAIT_NEXT_ARRAY_INFO)
						end = i
						//找到了一个array value，放入数组中
						tmpValue := jsonArrStack.Pop().([][]int)
						tmpValue = append(tmpValue, []int{start, end})
						jsonArrStack.Push(tmpValue)
						break
					} else if words[i] == '\\' {
						if i+1 < len(words) {
							i = i + 1
						} else {
							return nil, err
						}
					}
				}
			case words[i] == ']':
				stateStack.Pop()
			case words[i] == 't':
				if i+3 < len(words) {
					if words[i+1] == 'r' && words[i+2] == 'u' && words[i+3] == 'e' {
						stateStack.Pop()
						stateStack.Push(STATE_WAIT_NEXT_ARRAY_INFO)
						i = i + 3
					}
				} else {
					return nil, err
				}
			case words[i] == 'n':
				if i+3 < len(words) {
					if words[i+1] == 'u' && words[i+2] == 'l' && words[i+3] == 'l' {
						stateStack.Pop()
						stateStack.Push(STATE_WAIT_NEXT_ARRAY_INFO)
						i = i + 3
					}
				} else {
					return nil, err
				}
			case words[i] == 'f':
				if i+4 < len(words) {
					if words[i+1] == 'a' && words[i+2] == 'l' && words[i+3] == 's' && words[i+4] == 'e' {
						stateStack.Pop()
						stateStack.Push(STATE_WAIT_NEXT_ARRAY_INFO)
						i = i + 4
					}
				} else {
					return nil, err
				}
			case (words[i] >= '0' && words[i] <= '9') || words[i] == '.':
				for {
					if i+1 < len(words) {
						i = i + 1
					} else {
						return nil, err
					}
					if (words[i] >= '0' && words[i] <= '9') || words[i] == '.' {
						continue
					} else {
						i = i - 1
						stateStack.Pop()
						stateStack.Push(STATE_WAIT_NEXT_ARRAY_INFO)
						break
					}
				}
			case words[i] == '{':
				stateStack.Pop()
				stateStack.Push(STATE_WAIT_NEXT_ARRAY_INFO)
				stateStack.Push(STATE_WAIT_FIRST_MAP_KEY)

			case words[i] == '[':
				stateStack.Pop()
				stateStack.Push(STATE_WAIT_NEXT_ARRAY_INFO)
				stateStack.Push(STATE_WAIT_EACH_ARRAY_VALUE)
			default:
				return nil, err
			}
		case STATE_WAIT_NEXT_ARRAY_INFO:
			for {
				if words[i] == ',' {
					//只要数组最后一个元素
					jsonArrStack.Pop()
					stateStack.Pop()
					stateStack.Push(STATE_WAIT_EACH_ARRAY_VALUE)
					break
				} else if words[i] == ']' {
					stateStack.Pop()
					break
				} else if words[i] == ' ' || words[i] == '\n' || words[i] == '\t' || words[i] == '\r' {
					if i+1 < len(words) {
						i = i + 1
					} else {
						return nil, err
					}
				} else {
					return nil, err
				}
			}
		}
	}
loop:
	for {
		switch jsonArrStack.Peek().(type) {
		case [][]int:
			tmp := jsonArrStack.Pop()
			allResult = append(allResult, tmp.([][]int)...)
		default:
			break loop
		}
	}
	if stateStack.Peek().(int) == STATE_EMPTY {
		allResult = append(allResult, mapResult...);
		return allResult, nil
	} else {
		return nil, err
	}
}

//参数：url对象， 替换成什么关键词，更改模式（追加，替换），过滤器
func getPayloadList(query url.Values, payload string, mode int, filter *regexp.Regexp, parseJson bool) []string {
	result := []string{}
	for key, bValue := range query {
		for index, value := range query[key] {
			if parseJson {
				info, err := getParaStrValues(value)
				if err != nil {
					if filter == nil || filter.MatchString(value) {
						if mode == MODEREPLACE {
							query[key][index] = payload
						} else {
							query[key][index] = value + payload
						}
						result = append(result, query.Encode())
					}
				} else {
					words := ([]rune)(value)
					for i := 0; i < len(info); i++ {
						start := info[i][0]
						end := info[i][1]
						if filter == nil || filter.MatchString(Substr(value, start, end-start)) {
							if mode == MODEREPLACE {
								query[key][index] = Substr(value, 0, start) + payload + Substr(value, end, len(words)-end)
							} else {
								query[key][index] = Substr(value, 0, end) + payload + Substr(value, end, len(words)-end)
							}
							result = append(result, query.Encode())
						}
					}
				}
			} else {
				if filter == nil || filter.MatchString(value) {
					if mode == MODEREPLACE {
						query[key][index] = payload
					} else {
						query[key][index] = value + payload
					}
					result = append(result, query.Encode())
				}
			}
			query[key] = bValue
			query[key][index] = value
			//只对第一个参数进行修改：/?a=12&a=13&b=13 这种情况有两个a，只修改第一个a
			break
		}
	}
	return result
}

//追加参数：query对象，payload，过滤器，是否解析json
func GetAppendedPayloadList(query url.Values, payload string, filter *regexp.Regexp, parseJson bool) []string {
	return getPayloadList(query, payload, MODEAPPEND, filter, parseJson)
}

//替换参数：query对象，payload，过滤器，是否解析json
func GetReplacedPayloadList(query url.Values, payload string, filter *regexp.Regexp, parseJson bool) []string {
	return getPayloadList(query, payload, MODEREPLACE, filter, parseJson)
}

func getDataPayloadList(data, payload string, mode int, filter *regexp.Regexp, parseJson bool) []string {
	jsonInfo, err := getParaStrValues(data)
	if err != nil {
		queryData, err := url.ParseQuery(data)
		if err != nil {
			if filter == nil || filter.MatchString(data) {
				if mode == MODEREPLACE {
					return []string{payload}
				} else {
					return []string{data + payload}
				}
			} else {
				return []string{}
			}
		}
		return getPayloadList(queryData, payload, mode, filter, parseJson)
	}
	jsonResult := []string{}
	words := ([]rune)(data)
	for i := 0; i < len(jsonInfo); i++ {
		start := jsonInfo[i][0]
		end := jsonInfo[i][1]
		if filter == nil || filter.MatchString(Substr(data, start, end-start)) {
			if mode == MODEREPLACE {
				jsonResult = append(jsonResult, Substr(data, 0, start)+payload+Substr(data, end, len(words)-end))
			} else {
				jsonResult = append(jsonResult, Substr(data, 0, end)+payload+Substr(data, end, len(words)-end))
			}
		}
	}
	return jsonResult
}

func GetAppendedDataPayloadList(data, payload string, filter *regexp.Regexp, parseJson bool) []string {
	return getDataPayloadList(data, payload, MODEAPPEND, filter, parseJson)
}

func GetReplacedDataPayloadList(data, payload string, filter *regexp.Regexp, parseJson bool) []string {
	return getDataPayloadList(data, payload, MODEREPLACE, filter, parseJson)
}
