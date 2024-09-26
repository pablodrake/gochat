package gochatterminal

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// Global mutex to synchronize terminal output
var stdoutMutex sync.Mutex

// Terminal struct handles user input and terminal state
type Terminal struct {
	inputRequests chan InputRequest
	history       []string
	historyIndex  int
	cursorPos     int
	prompt        string
	currentLine   string
	mu            sync.Mutex // Protects currentLine
	oldState      *term.State
	isRawMode     bool // Indicates if the terminal is in raw mode
}

// InputRequest represents a request for user input.
type InputRequest struct {
	Prompt   string
	Response chan string
}

// NewTerminal initializes a new Terminal instance.
func NewTerminal(prompt string) (*Terminal, error) {
	t := &Terminal{
		inputRequests: make(chan InputRequest),
		prompt:        prompt,
		historyIndex:  0,
		isRawMode:     false, // Initialize as not in raw mode
	}

	go t.inputManager()
	return t, nil
}

func (t *Terminal) inputManager() {
	for req := range t.inputRequests {
		stdoutMutex.Lock()
		fmt.Print("\r" + req.Prompt)
		stdoutMutex.Unlock()

		var line string

		if t.isRawMode {
			// Use the raw mode input handling
			line = t.readLineRawMode(req.Prompt)
		} else {
			// Use normal mode input handling
			line = t.readLineNormalMode(req.Prompt)
		}

		// Send the line back to the requester
		req.Response <- line
	}
}

func (t *Terminal) readLineNormalMode(prompt string) string {
	reader := bufio.NewReader(os.Stdin)

	stdoutMutex.Lock()
	fmt.Print("\r" + prompt)
	stdoutMutex.Unlock()

	line, err := reader.ReadString('\n')
	if err != nil {
		t.PrintMessage("Error reading input.", true)
		return ""
	}

	line = strings.TrimRight(line, "\r\n")
	t.history = append(t.history, line)

	// Reset currentLine and cursorPos
	t.mu.Lock()
	t.currentLine = ""
	t.cursorPos = 0
	t.mu.Unlock()

	return line
}

func (t *Terminal) readLineRawMode(prompt string) string {
	var line []rune
	t.mu.Lock()
	t.currentLine = ""
	t.mu.Unlock()
	t.cursorPos = 0
	historyIndex := len(t.history)

	for {
		// Read a single byte
		var buf [1]byte
		n, err := os.Stdin.Read(buf[:])
		if err != nil || n == 0 {
			t.PrintMessage("Error reading input.", true)
			return ""
		}
		r := rune(buf[0])

		if r == '\r' || r == '\n' {
			// Newline detected, process the line
			inputLine := string(line)
			t.history = append(t.history, inputLine)
			t.mu.Lock()
			t.currentLine = ""
			t.mu.Unlock()
			stdoutMutex.Lock()
			fmt.Print("\r\n") // Move to the next line
			stdoutMutex.Unlock()
			return inputLine
		} else if r == 127 || r == '\b' {
			// Handle backspace
			if t.cursorPos > 0 {
				line = append(line[:t.cursorPos-1], line[t.cursorPos:]...)
				t.cursorPos--

				t.mu.Lock()
				t.currentLine = string(line)
				t.mu.Unlock()

				// Re-render the line
				t.renderLine(prompt, line)
			}
		} else if r == 3 {
			// Handle Ctrl+C
			stdoutMutex.Lock()
			fmt.Print("^C\r\n")
			stdoutMutex.Unlock()
			return ""
		} else if r == 4 {
			// Handle Ctrl+D (EOF)
			return ""
		} else if r == 0x1b { // ESC character
			// Read the next two bytes to identify the escape sequence
			var seq [2]byte
			n, err := os.Stdin.Read(seq[:])
			if err != nil || n < 2 {
				t.PrintMessage("Error reading escape sequence.", true)
				continue // Skip processing this escape sequence
			}

			if seq[0] == '[' {
				switch seq[1] {
				case 'A': // Up Arrow
					if historyIndex > 0 {
						historyIndex--
						// Retrieve the previous command from history
						historyLine := t.history[historyIndex]
						// Update the current line with the history entry
						line = []rune(historyLine)
						t.mu.Lock()
						t.currentLine = historyLine
						t.mu.Unlock()
						// Set cursor position to the end of the line
						t.cursorPos = len(line)
						// Re-render the line
						t.renderLine(prompt, line)
					}
				case 'B': // Down Arrow
					if historyIndex < len(t.history)-1 {
						historyIndex++
						// Retrieve the next command from history
						historyLine := t.history[historyIndex]
						// Update the current line with the history entry
						line = []rune(historyLine)
						t.mu.Lock()
						t.currentLine = historyLine
						t.mu.Unlock()
						// Set cursor position to the end of the line
						t.cursorPos = len(line)
						// Re-render the line
						t.renderLine(prompt, line)
					} else if historyIndex == len(t.history)-1 {
						historyIndex++
						// Reset the current line
						line = nil
						t.mu.Lock()
						t.currentLine = ""
						t.mu.Unlock()
						// Set cursor position to the beginning
						t.cursorPos = 0
						// Re-render the prompt
						t.renderLine(prompt, line)
					}
				case 'C': // Right Arrow
					if t.cursorPos < len(line) {
						t.cursorPos++
						stdoutMutex.Lock()
						fmt.Print("\x1b[1C") // Move cursor right
						stdoutMutex.Unlock()
					}
				case 'D': // Left Arrow
					if t.cursorPos > 0 {
						t.cursorPos--
						stdoutMutex.Lock()
						fmt.Print("\x1b[1D") // Move cursor left
						stdoutMutex.Unlock()
					}
				default:
					// Handle other escape sequences if necessary
				}
			}
		} else {
			// Add the rune to the line at cursorPos
			line = append(line[:t.cursorPos], append([]rune{r}, line[t.cursorPos:]...)...)
			t.cursorPos++

			t.mu.Lock()
			t.currentLine = string(line)
			t.mu.Unlock()

			// Re-render the line
			t.renderLine(prompt, line)

			// Reset history index since user is typing a new command
			historyIndex = len(t.history)
		}
	}
}

// ReadLine reads a line from the terminal using the default prompt.
func (t *Terminal) ReadLine() (string, error) {
	return t.ReadLineWithPrompt(t.prompt)
}

// ReadLineWithPrompt reads a line using a specified prompt.
func (t *Terminal) ReadLineWithPrompt(prompt string) (string, error) {
	responseChan := make(chan string)
	t.inputRequests <- InputRequest{
		Prompt:   prompt,
		Response: responseChan,
	}
	line := <-responseChan
	return line, nil
}

func (t *Terminal) clearCurrentInput() {
	stdoutMutex.Lock()
	defer stdoutMutex.Unlock()
	fmt.Print("\r\033[K") // Move cursor to start of line and clear the line
}

// renderLine redraws the current input line and positions the cursor correctly.
func (t *Terminal) renderLine(prompt string, line []rune) {
	stdoutMutex.Lock()
	defer stdoutMutex.Unlock()

	// Move cursor to the beginning and clear the line
	fmt.Print("\r\033[K")

	// Print the prompt and the line
	fmt.Print(prompt + string(line))

	// Move cursor to the correct position
	if t.cursorPos < len(line) {
		// Move cursor back to the cursorPos
		backSpaces := len(line) - t.cursorPos
		fmt.Printf("\x1b[%dD", backSpaces)
	}
}

// SetPrompt updates the terminal prompt.
func (t *Terminal) SetPrompt(prompt string) {
	t.prompt = prompt
}

// Close terminates the input manager goroutine and restores terminal state.
func (t *Terminal) Close() {
	t.clearCurrentInput()
	t.RestoreState()
	close(t.inputRequests)
}

// PrintMessage prints a message to the terminal in a thread-safe manner.
func (t *Terminal) PrintMessage(message string, restorePrompt bool) {
	t.mu.Lock()
	line := t.currentLine
	cursorPos := t.cursorPos
	t.mu.Unlock()

	t.clearCurrentInput()

	stdoutMutex.Lock()
	defer stdoutMutex.Unlock()
	fmt.Println("\r" + message)
	if restorePrompt {
		fmt.Print("\r" + t.prompt + line)
	} else {
		fmt.Print("\r")
	}

	// Move cursor to the correct position
	if cursorPos < len([]rune(line)) {
		backSpaces := len([]rune(line)) - cursorPos
		fmt.Printf("\x1b[%dD", backSpaces)
	}
}

// AskYesNo prompts the user with a question and expects a yes/no response.
func (t *Terminal) AskYesNo(prompt string) bool {
	for {
		response, err := t.ReadLineWithPrompt(prompt)
		if err != nil {
			t.PrintMessage("Error reading input. Please try again.", false)
			continue
		}
		response = strings.TrimSpace(strings.ToLower(response))
		if response == "yes" || response == "y" {
			return true
		}
		if response == "no" || response == "n" {
			return false
		}
		t.PrintMessage("Please answer 'yes' or 'no'.", false)
	}
}

func (t *Terminal) SetRawMode() error {
	fd := int(os.Stdin.Fd())

	// Save the old terminal state
	oldState, err := term.GetState(fd)
	if err != nil {
		return fmt.Errorf("failed to get terminal state: %w", err)
	}

	// Put the terminal into raw mode
	if _, err := term.MakeRaw(fd); err != nil {
		return fmt.Errorf("failed to put terminal into raw mode: %w", err)
	}

	// Retrieve the current terminal attributes
	termios, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return fmt.Errorf("failed to retrieve the current terminal attributes: %w", err)
	}

	// Re-enable ISIG to allow signal generation from characters like Ctrl+C
	termios.Lflag |= unix.ISIG

	// Apply the modified terminal attributes
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, termios); err != nil {
		return fmt.Errorf("failed to apply the modified terminal attributes: %w", err)
	}

	t.oldState = oldState
	t.isRawMode = true
	return nil
}

func (t *Terminal) RestoreState() error {
	if t.oldState != nil {
		term.Restore(int(os.Stdin.Fd()), t.oldState)
		t.isRawMode = false
	}
	return nil
}
