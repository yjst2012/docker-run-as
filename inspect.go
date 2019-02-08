package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"git.unitecloud.net/bahus.vel/CRaaSH/ccssh"
)

type DockerInspect struct {
	Name      string
	Container string
	Output    string
	Facts     map[string]interface{}
	Options   []string
	Pretty    bool
	//App       *DockerApp
}

func Create(host, container string) (*DockerInspect, error) {

	output, err := ccssh.Command(host, "docker", "inspect", container).Output()
	if err != nil {
		log.Println("docker inspect err on", host, err)
		return nil, err
	}
	var facts map[string]interface{}
	err = json.Unmarshal(output, &facts)
	inspect := DockerInspect{Name: host, Container: container, Output: string(output), Facts: facts, Pretty: true}
	return &inspect, nil
}

func Read(output []byte) (*DockerInspect, error) {

	var facts map[string]interface{}
	err := json.Unmarshal(output, &facts)
	if err != nil {
		log.Println("err unmarshal", string(output))
		return nil, err
	}
	inspect := DockerInspect{Output: string(output), Facts: facts, Pretty: true}
	//log.Println("unmarshaled", inspect)
	return &inspect, nil
}

func (self *DockerInspect) GetFact(path string) (string, error) {

	parts := strings.Split(path, ".")
	m := self.Facts

	for i := 0; i < len(parts)-1; i++ {
		p := parts[i]
		m = m[p].(map[string]interface{})
	}
	v := reflect.ValueOf(m[parts[len(parts)-1]])
	if v.Kind() != reflect.String {
		log.Println("target at", path, "is not string #", v.Kind())
		return "", errors.New("target is not a string!")
	}

	value := m[parts[len(parts)-1]].(string)
	return value, nil
}

// for slice of multiple strings
func (self *DockerInspect) GetFactStringSlice(path string) ([]string, error) {
	facts, err := self.GetFactInterface(path)
	if err != nil {
		log.Println("error in get facts", err)
		return []string{}, err
	}
	if facts == nil || reflect.ValueOf(facts).IsNil() {
		return []string{}, nil
	}
	//log.Println("factss", facts, reflect.ValueOf(facts).Kind())

	v := reflect.ValueOf(facts)
	if v.Kind() != reflect.Slice {
		log.Println("wrong type of", path, v.Kind())
		return []string{}, nil
	}
	str := []string{}
	for i := 0; i < v.Len(); i++ {
		val := v.Index(i).Interface().(string)
		str = append(str, val)
	}
	return str, nil
}

func (self *DockerInspect) GetFactBool(path string) (bool, error) {

	parts := strings.Split(path, ".")
	m := self.Facts

	for i := 0; i < len(parts)-1; i++ {
		p := parts[i]
		m = m[p].(map[string]interface{})
	}
	value := m[parts[len(parts)-1]].(bool)
	return value, nil
}

func (self *DockerInspect) GetFactMap(path string) (map[string]interface{}, error) {

	parts := strings.Split(path, ".")
	m := self.Facts

	for i := 0; i < len(parts); i++ {
		p := parts[i]
		i := m[p]
		//fmt.Printf("type is %T", i)
		m = i.(map[string]interface{})
		//log.Println("part", p, "value", m)
	}
	return m, nil
}

func (self *DockerInspect) GetFactInterface(path string) (interface{}, error) {

	parts := strings.Split(path, ".")
	m := self.Facts

	for i := 0; i < len(parts)-1; i++ {
		p := parts[i]
		switch m[p].(type) {
		case map[string]interface{}:
			m = m[p].(map[string]interface{})
		default:
			fmt.Printf("alert, value(%T) is not a map, incompatible type\n", m[p])
			return nil, errors.New("alert, value is not a map, incompatible type\n")
		}
	}
	if m[parts[len(parts)-1]] == nil {
		return nil, nil
	}
	return m[parts[len(parts)-1]], nil
}

// for slice of multiple strings
func (self *DockerInspect) MultiOption(path, option string) error {
	//log.Println("path", path, "options", option)
	facts, err := self.GetFactInterface(path) // facts is interface{}
	if err != nil {
		log.Println("error in get facts", err)
		return err
	}
	if facts == nil || reflect.ValueOf(facts).IsNil() {
		return nil
	}
	//log.Println("facts", facts, reflect.ValueOf(facts).Kind())

	v := reflect.ValueOf(facts)
	if v.Kind() != reflect.Slice {
		log.Println("wrong type of", path, v.Kind())
		return nil
	}
	for i := 0; i < v.Len(); i++ {
		val := v.Index(i).Interface().(string)
		value := fmt.Sprintf("--%s=%s", option, quote(val))
		self.Options = append(self.Options, value)
	}
	return nil
}

func (self *DockerInspect) ParseHostname() error {

	hostname, err := self.GetFact("Config.Hostname")
	if err != nil {
		log.Println("get host name err", err)
		return err
	}
	value := fmt.Sprintf("--hostname=%s", hostname)
	self.Options = append(self.Options, value)
	return nil
}

func (self *DockerInspect) ParseUser() error {

	user, err := self.GetFact("Config.User")
	if err != nil {
		log.Println("get user err", err)
		return err
	}
	value := fmt.Sprintf("--user=%s", user)
	self.Options = append(self.Options, value)
	return nil
}

func (self *DockerInspect) ParsePorts() error {

	ports, err := self.GetFactMap("NetworkSettings.Ports")
	if err != nil {
		log.Println("get ports error", err)
		return err
	}
	bindings, err := self.GetFactMap("HostConfig.PortBindings")
	if err != nil {
		log.Println("get portbindings error", err)
		return err
	}
	for key, value := range bindings {
		ports[key] = value
	}

	if ports != nil {
		for container_port_and_protocol, val := range ports {
			if strings.HasSuffix(container_port_and_protocol, "/tcp") {
				container_port_and_protocol = strings.TrimSuffix(container_port_and_protocol, "/tcp")
			}
			v := reflect.ValueOf(val)
			if v.Kind() == reflect.String && (val.(string) == "" || val.(string) == "null") {
				self.Options = append(self.Options, "--expose="+container_port_and_protocol)
			} else if v.Kind() == reflect.Slice {

				for _, m := range val.([]interface{}) {
					options := m.(map[string]interface{})
					host_ip := options["HostIp"].(string)
					host_port := options["HostPort"].(string)
					if host_port == "" {
						self.Options = append(self.Options, "-p "+container_port_and_protocol)
					} else {
						if host_ip != "" {
							self.Options = append(self.Options,
								fmt.Sprintf("-p %s:%s:%s", host_ip, host_port, container_port_and_protocol))
						} else {
							self.Options = append(self.Options,
								fmt.Sprintf("-p %s:%s", host_port, container_port_and_protocol))
						}
					}
				}
			} else {
				log.Panic("bad type ", v.Kind())
			}
		}

	}
	return nil
}

func (self *DockerInspect) ParseRestart() error {
	restart, err := self.GetFact("HostConfig.RestartPolicy.Name")
	if err != nil {
		log.Println("get fact HostConfig.RestartPolicy.Name err", err)
		return err
	}
	if restart == "no" {
		return nil
	} else if restart == "on-failure" {
		max_retries, err := self.GetFact(
			"HostConfig.RestartPolicy.MaximumRetryCount")
		if err != nil {
			number, err1 := strconv.Atoi(max_retries)
			if err1 != nil && number > 0 {
				restart += ":" + max_retries
			}
		}
	}
	self.Options = append(self.Options, "--restart="+restart)
	return nil
}

func (self *DockerInspect) ParseLabels() error {
	labels, err := self.GetFactMap("Config.Labels")
	if err != nil {
		log.Println("get fact Config.Labels err", err)
		return err
	}
	label_options := []string{}
	if len(labels) > 0 {
		for key, value := range labels {
			label_options = append(label_options, fmt.Sprintf("--label %s=\"%s\"", key, value))
		}
	}
	self.Options = append(self.Options, label_options...)
	return nil
}

func (self *DockerInspect) ParseDevices() error {

	facts, err := self.GetFactInterface("HostConfig.Devices")
	if err != nil {
		log.Println("error in getting HostConfig.Devices", err)
		return err
	}
	if facts == nil || reflect.ValueOf(facts).IsNil() {
		return nil
	}
	log.Println("facts", facts)

	v := reflect.ValueOf(facts)
	if v.Kind() != reflect.Slice {
		log.Println("wrong type of HostConfig.Devices", v.Kind())
		return nil
	}
	device_options := []string{}
	for i := 0; i < v.Len(); i++ {
		device := v.Index(i).Interface().(map[string]string)
		host := device["PathOnHost"]
		container := device["PathInContainer"]
		perms := device["CgroupPermissions"]
		spec := host + ":" + container
		if perms != "rwm" {
			spec += ":" + perms
		}
		device_options = append(device_options, "--device "+spec)
	}
	self.Options = append(self.Options, device_options...)
	return nil
}

func (self *DockerInspect) ParseLogs() error {
	log_type, err := self.GetFact("HostConfig.LogConfig.Type")
	if err != nil {
		log.Println("get fact Config.Labels err", err)
		return err
	}
	log_opts, err := self.GetFactMap("HostConfig.LogConfig.Config")
	if err != nil {
		log.Println("get fact HostConfig.LogConfig.Config err", err)
		return err
	}
	log_options := []string{}
	if log_type != "json-file" {
		log_options = append(log_options, "--log-driver="+log_type)
	}
	if len(log_opts) > 0 {
		for key, value := range log_opts {
			val := value.(string)
			log_options = append(log_options, "--log-opt "+key+"="+val)
		}
	}
	self.Options = append(self.Options, log_options...)
	return nil
}

func (self *DockerInspect) ParseExtraHosts() error {

	hosts, err := self.GetFactStringSlice("HostConfig.ExtraHosts")
	if err != nil {
		log.Println("get fact HostConfig.ExtraHosts err", err)
		return err
	}
	for _, host := range hosts {
		self.Options = append(self.Options, "--add-host "+host)
	}
	return nil
}

func (self *DockerInspect) ParseVolumes() error {

	volumes, err := self.GetFactMap("Config.Volumes")
	if err != nil {
		log.Println("get fact Config.Volumes err", err)
		return err
	}
	for key, val := range volumes {
		str := fmt.Sprintf("--volume=%s", key)
		value := val.(map[string]interface{})
		if len(value) > 0 {
			// maybe not correct format
			for x, y := range value {
				if x != "" {
					str = str + ":" + quote(x)
				}
				if y != "" {
					str = str + ":" + quote(y.(string))
				}

			}
		}
		self.Options = append(self.Options, str)
	}
	return nil
}

func (self *DockerInspect) ParseLinks() error {
	links, err := self.GetFactStringSlice("HostConfig.Links")
	if err != nil {
		log.Println("get fact HostConfig.Links err", err)
		return err
	}
	link_options := []string{}
	if len(links) > 0 {
		for _, link := range links {
			str := strings.Split(link, ":")
			src := str[0]
			dst := str[1]
			s := strings.Split(src, "/")
			d := strings.Split(dst, "/")
			source := s[len(s)-1]
			dest := d[len(d)-1]
			if source != dest {
				link_options = append(link_options, fmt.Sprintf("--link %s:%s", source, dest))
			} else {
				link_options = append(link_options, "--link "+source)
			}
		}
	}
	self.Options = append(self.Options, link_options...)
	return nil
}

func (self *DockerInspect) ParseMacaddress() error {

	defer func() {
		if r := recover(); r != nil {
			log.Println("cannot find Config.MacAddress", r)
			return
		}
	}()
	mac_address, err := self.GetFact("Config.MacAddress")
	if err != nil {
		log.Println("get fact Config.MacAddress err", err)
		return err
	}
	self.Options = append(self.Options, "--mac-address="+mac_address)
	return nil
}

func quote(part string) string {

	match, _ := regexp.MatchString("\\s", part)
	if match {
		new := strings.Replace(part, "'", "\\'", -1)
		return fmt.Sprintf("'%s'", new)
	}
	return part
}

func (self *DockerInspect) FormatCli() (string, error) {
	self.Output = "docker run "

	image, err := self.GetFact("Config.Image")
	if err != nil {
		log.Println("get fact image err", err)
		return "", err
	}
	self.Options = []string{}

	name, err := self.GetFact("Name")
	if err == nil {
		n := strings.Split(name, "/")
		if len(n) > 0 {
			self.Options = append(self.Options, "--name="+n[1])
		}
	}

	self.ParseHostname()
	self.ParseUser()
	self.ParseMacaddress()

	self.MultiOption("Config.Env", "env")
	self.MultiOption("HostConfig.Binds", "volume")
	self.MultiOption("HostConfig.VolumesFrom", "volumes-from")
	self.MultiOption("HostConfig.CapAdd", "cap-add")
	self.MultiOption("HostConfig.CapDrop", "cap-drop")
	network_mode, err := self.GetFact("HostConfig.NetworkMode")
	if err != nil {
		log.Println("get fact HostConfig.NetworkMode err", err)
		return "", err
	}
	if network_mode != "default" {
		self.Options = append(self.Options, "--network="+network_mode)
	}
	privileged, err := self.GetFactBool("HostConfig.Privileged")
	if err != nil {
		log.Println("get fact HostConfig.Privileged err", err)
		return "", err
	}
	if privileged {
		self.Options = append(self.Options, "--privileged")
	}
	self.ParseVolumes()
	self.ParsePorts()
	self.ParseLinks()
	self.ParseRestart()
	self.ParseDevices()
	self.ParseLabels()
	self.ParseLogs()
	self.ParseExtraHosts()

	stdout_attached, err := self.GetFactBool("Config.AttachStdout")
	if err != nil {
		log.Println("get fact Config.AttachStdout err", err)
		return "", err
	}
	if stdout_attached {
		self.Options = append(self.Options, "--detach=true")
	}
	tty, err := self.GetFactBool("Config.Tty")
	if err != nil && tty {
		self.Options = append(self.Options, "-t")
	}

	parameters := []string{"run"}
	if len(self.Options) > 0 {
		parameters = append(parameters, self.Options...)
	}
	parameters = append(parameters, image)

	cmd, err := self.GetFactInterface("Config.Cmd")
	if err != nil {
		log.Println("get fact Config.Cmd err", err)
		return "", err
	}
	v := reflect.ValueOf(cmd)
	if v.Kind() == reflect.Slice {
		for i := 0; i < v.Len(); i++ {
			cmd := v.Index(i).Interface().(string)
			parameters = append(parameters, quote(cmd))
		}
	}
	joiner := " "
	if self.Pretty {
		joiner += "\\\n\t"
	}
	para := strings.Join(parameters, joiner)
	return "docker " + para, nil
}

func main() {
	data, err := ioutil.ReadFile("./inspect_test.json")
	if err != nil {
		log.Println(err, "Could not read nodefile")
		return
	}
	ins, err := Read(data)
	if err != nil {
		log.Println(err, "Could not read data", string(data))
		return
	}
	out, err := ins.FormatCli()

	log.Println("output cmd:\n", out)
	if err != nil {
		log.Println(err, "Could not format cli nodefile")
		return
	}
	return
}
