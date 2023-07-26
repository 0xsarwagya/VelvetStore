package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os"
	"sync"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/sirupsen/logrus"
)

type User struct {
	Username string    `json:"username"`
	Password string    `json:"password"`
	Projects []Project `json:"projects"`
}

type Project struct {
	ProjectID string `json:"project_id"`
	APIKey    string `json:"api_key"`
}

type UserData struct {
	Data     map[string]string
	Projects map[string]string
	mu       sync.Mutex
}

type VelvetStore struct {
	users        map[string]User
	userData     map[string]*UserData
	mu           sync.Mutex
	authorized   bool
	subscribe    chan chan map[string]string
	loggedInUser string
	clients      map[*websocket.Conn]bool
}

func NewVelvetStore() *VelvetStore {
	db := &VelvetStore{
		users:        make(map[string]User),
		userData:     make(map[string]*UserData),
		authorized:   false,
		subscribe:    make(chan chan map[string]string),
		loggedInUser: "",
		clients:      make(map[*websocket.Conn]bool),
	}

	go db.notifyClients()
	return db
}

func (db *VelvetStore) SignupHandler(w http.ResponseWriter, r *http.Request) {
	if db.authorized {
		http.Error(w, "Already logged in", http.StatusForbidden)
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
		return
	}

	var user User
	err = json.Unmarshal(body, &user)
	if err != nil {
		http.Error(w, "Error parsing request body", http.StatusBadRequest)
		return
	}

	db.mu.Lock()
	defer db.mu.Unlock()
	if _, exists := db.users[user.Username]; exists {
		http.Error(w, "Username already exists", http.StatusBadRequest)
		return
	}

	user.Projects = make([]Project, 0)
	db.users[user.Username] = user
	err = db.saveUsersToFile()
	if err != nil {
		http.Error(w, "Error saving user data", http.StatusInternalServerError)
		return
	}

	respBody, err := json.Marshal(user)
	if err != nil {
		http.Error(w, "Error creating response", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Header().Set("Content-Type", "application/json")
	w.Write(respBody)
}

func (db *VelvetStore) LoginHandler(w http.ResponseWriter, r *http.Request) {
	if db.authorized {
		http.Error(w, "Already logged in", http.StatusForbidden)
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
		return
	}

	var user User
	err = json.Unmarshal(body, &user)
	if err != nil {
		http.Error(w, "Error parsing request body", http.StatusBadRequest)
		return
	}

	db.mu.Lock()
	defer db.mu.Unlock()
	existingUser, exists := db.users[user.Username]
	if !exists || existingUser.Password != user.Password {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	db.authorized = true
	db.loggedInUser = user.Username

	if len(existingUser.Projects) > 0 {
		apiKey := existingUser.Projects[0].APIKey
		respBody, err := json.Marshal(map[string]string{
			"api_key": apiKey,
		})
		if err != nil {
			http.Error(w, "Error creating response", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Header().Set("Content-Type", "application/json")
		w.Write(respBody)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (db *VelvetStore) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	if !db.authorized {
		http.Error(w, "Not logged in", http.StatusUnauthorized)
		return
	}

	db.authorized = false
	db.loggedInUser = ""
	w.WriteHeader(http.StatusOK)
}

func (db *VelvetStore) CreateProjectHandler(w http.ResponseWriter, r *http.Request) {
	if !db.authorized {
		http.Error(w, "Not logged in", http.StatusUnauthorized)
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
		return
	}

	var project Project
	err = json.Unmarshal(body, &project)
	if err != nil {
		http.Error(w, "Error parsing request body", http.StatusBadRequest)
		return
	}

	username := db.getLoggedInUser()
	db.mu.Lock()
	defer db.mu.Unlock()
	user, exists := db.users[username]
	if !exists {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	project.APIKey = db.generateAPIKey()
	user.Projects = append(user.Projects, project)
	db.users[username] = user
	err = db.saveUsersToFile()
	if err != nil {
		http.Error(w, "Error saving user data", http.StatusInternalServerError)
		return
	}

	respBody, err := json.Marshal(project)
	if err != nil {
		http.Error(w, "Error creating response", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	w.Header().Set("Content-Type", "application/json")
	w.Write(respBody)
}

func (db *VelvetStore) SetHandler(w http.ResponseWriter, r *http.Request) {
	if !db.authorized {
		http.Error(w, "Not logged in", http.StatusUnauthorized)
		return
	}

	projectID := r.FormValue("project_id")
	apiKey, exists := db.getProjectAPIKey(projectID)
	if !exists {
		http.Error(w, "Project not found", http.StatusNotFound)
		return
	}

	if r.Header.Get("Authorization") != apiKey {
		http.Error(w, "Unauthorized access", http.StatusForbidden)
		return
	}

	username := db.getLoggedInUser()
	db.mu.Lock()
	userData, exists := db.userData[username]
	db.mu.Unlock()
	if !exists {
		http.Error(w, "User data not found", http.StatusNotFound)
		return
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Error reading request body", http.StatusInternalServerError)
		return
	}

	var data map[string]string
	err = json.Unmarshal(body, &data)
	if err != nil {
		http.Error(w, "Error parsing request body", http.StatusBadRequest)
		return
	}

	userData.mu.Lock()
	for key, value := range data {
		userData.Data[key] = value
	}
	userData.mu.Unlock()

	go db.notifySubscribers()

	w.WriteHeader(http.StatusOK)
}

func (db *VelvetStore) GetHandler(w http.ResponseWriter, r *http.Request) {
	if !db.authorized {
		http.Error(w, "Not logged in", http.StatusUnauthorized)
		return
	}

	projectID := r.FormValue("project_id")
	apiKey, exists := db.getProjectAPIKey(projectID)
	if !exists {
		http.Error(w, "Project not found", http.StatusNotFound)
		return
	}

	if r.Header.Get("Authorization") != apiKey {
		http.Error(w, "Unauthorized access", http.StatusForbidden)
		return
	}

	username := db.getLoggedInUser()
	db.mu.Lock()
	userData, exists := db.userData[username]
	db.mu.Unlock()
	if !exists {
		http.Error(w, "User data not found", http.StatusNotFound)
		return
	}

	respBody, err := json.Marshal(userData.Data)
	if err != nil {
		http.Error(w, "Error creating response", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(respBody)
}

func (db *VelvetStore) GetAPIKeyHandler(w http.ResponseWriter, r *http.Request) {
	if !db.authorized {
		http.Error(w, "Not logged in ", http.StatusUnauthorized)
		return
	}

	username := db.getLoggedInUser()
	db.mu.Lock()
	defer db.mu.Unlock()
	user, exists := db.users[username]
	if !exists || len(user.Projects) == 0 {
		http.Error(w, "User or project not found", http.StatusNotFound)
		return
	}

	apiKey := user.Projects[0].APIKey
	respBody, err := json.Marshal(map[string]string{
		"api_key": apiKey,
	})
	if err != nil {
		http.Error(w, "Error creating response", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Write(respBody)
}

func (db *VelvetStore) generateAPIKey() string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 32)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

func (db *VelvetStore) saveToFile(username string) error {
	userData, exists := db.userData[username]
	if !exists {
		return fmt.Errorf("user data not found for username: %s", username)
	}

	data, err := json.Marshal(userData.Data)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(fmt.Sprintf("./database/%s.json", username), data, 0644)
	if err != nil {
		return err
	}

	return nil
}

func (db *VelvetStore) loadFromFile(username string) error {
	data, err := ioutil.ReadFile(fmt.Sprintf("./database/%s.json", username))
	if err != nil {
		return err
	}

	userData := &UserData{
		Data: make(map[string]string),
	}

	err = json.Unmarshal(data, &userData.Data)
	if err != nil {
		return err
	}

	db.userData[username] = userData

	return nil
}

func (db *VelvetStore) saveUsersToFile() error {
	data, err := json.Marshal(db.users)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile("./admin/users.json", data, 0644)
	if err != nil {
		return err
	}

	return nil
}

func (db *VelvetStore) loadUsersFromFile() error {
	data, err := ioutil.ReadFile("./admin/users.json")
	if err != nil {
		return err
	}

	err = json.Unmarshal(data, &db.users)
	if err != nil {
		return err
	}

	return nil
}

func (db *VelvetStore) getLoggedInUser() string {
	return db.loggedInUser
}

func (db *VelvetStore) getProjectAPIKey(projectID string) (string, bool) {
	username := db.getLoggedInUser()
	user, exists := db.users[username]
	if !exists {
		return "", false
	}

	for _, project := range user.Projects {
		if project.ProjectID == projectID {
			return project.APIKey, true
		}
	}

	return "", false
}

func (db *VelvetStore) notifyClients() {
	for {
		select {
		case client := <-db.subscribe:
			client <- db.userData[db.loggedInUser].Data
		}
	}
}

func (db *VelvetStore) notifySubscribers() {
	username := db.getLoggedInUser()
	client := <-db.subscribe
	client <- db.userData[username].Data
}

func (db *VelvetStore) handleWebSocketConnections() {
	for {
		select {
		case client := <-db.subscribe:
			username := db.getLoggedInUser()
			userData, exists := db.userData[username]
			if exists {
				client <- userData.Data
			}
		}
	}
}

func (db *VelvetStore) WebSocketHandler(w http.ResponseWriter, r *http.Request) {
	// Upgrade HTTP connection to WebSocket
	conn, err := websocket.Upgrade(w, r, nil, 1024, 1024)
	if err != nil {
		http.Error(w, "Failed to upgrade to WebSocket", http.StatusInternalServerError)
		return
	}

	// Add the client to the list of connected clients
	db.mu.Lock()
	db.clients[conn] = true
	db.mu.Unlock()

	// Handle incoming messages from the client (if needed)
	go db.handleWebSocketMessages(conn)

	// Close the connection when the client disconnects
	defer func() {
		db.mu.Lock()
		delete(db.clients, conn)
		db.mu.Unlock()
		conn.Close()
	}()
}

func (db *VelvetStore) handleWebSocketMessages(conn *websocket.Conn) {
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

var log = logrus.New()

func init() {
	log.SetFormatter(&logrus.JSONFormatter{})
	log.SetOutput(os.Stdout)
	log.SetLevel(logrus.InfoLevel)
}

func main() {
	db := NewVelvetStore()

	if err := db.loadUsersFromFile(); err != nil {
		log.WithError(err).Error("Error loading users")
		return
	}

	r := mux.NewRouter()

	go db.handleWebSocketConnections()

	r.HandleFunc("/signup", db.SignupHandler).Methods("POST")
	r.HandleFunc("/login", db.LoginHandler).Methods("POST")
	r.HandleFunc("/logout", db.LogoutHandler).Methods("POST")
	r.HandleFunc("/create_project", db.CreateProjectHandler).Methods("POST")
	r.HandleFunc("/set", db.SetHandler).Methods("POST")
	r.HandleFunc("/get", db.GetHandler).Methods("GET")
	r.HandleFunc("/api_key", db.GetAPIKeyHandler).Methods("GET")
	r.HandleFunc("/ws", db.WebSocketHandler)

	http.Handle("/", r)

	go db.handleWebSocketConnections()

	log.Info("Listening on :8080...")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.WithError(err).Fatal("HTTP server failed to start")
	}
}
