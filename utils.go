package onvif

func interfaceToString(src interface{}) string {
	data, _ := src.(string)
	return data
}
