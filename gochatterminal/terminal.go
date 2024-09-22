// gochatterminal/terminal.go
package gochatterminal

import (
	"fmt"
	"os"
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
	prompt        string
	currentLine   string
	mu            sync.Mutex // Protects currentLine
	oldState      *term.State
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
	}

	fd := int(os.Stdin.Fd())

	// Save the old terminal state
	oldState, err := term.GetState(fd)
	if err != nil {
		return t, fmt.Errorf("failed to get terminal state: +%w", err)
	}

	// Put the terminal into raw mode
	if _, err := term.MakeRaw(fd); err != nil {
		return t, fmt.Errorf("failed to put terminal into raw mode: %w", err)
	}

	// Retrieve the current terminal attributes
	termios, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	if err != nil {
		return t, fmt.Errorf("failed to retrieve the current terminal attributes: %w", err)
	}

	// Re-enable ISIG to allow signal generation from characters like Ctrl+C
	termios.Lflag |= unix.ISIG

	// Apply the modified terminal attributes
	if err := unix.IoctlSetTermios(fd, unix.TCSETS, termios); err != nil {
		return t, fmt.Errorf("failed to apply the modified terminal attributes: %w", err)
	}

	t.oldState = oldState

	go t.inputManager()
	return t, nil
}

func (t *Terminal) inputManager() {
	for req := range t.inputRequests {
		stdoutMutex.Lock()
		fmt.Print("\r" + req.Prompt) // Move to the start of the line before printing the prompt
		stdoutMutex.Unlock()

		var line []rune
		t.mu.Lock()
		t.currentLine = "" // Initialize currentLine
		t.mu.Unlock()

		// Initialize history index to point beyond the last element
		historyIndex := len(t.history)

		for {
			// Read a single byte
			var buf [1]byte
			n, err := os.Stdin.Read(buf[:])
			if err != nil || n == 0 {
				t.PrintMessage("Error reading input.")
				req.Response <- ""
				break
			}
			r := rune(buf[0])

			if r == '\r' || r == '\n' {
				// Newline detected, process the line
				inputLine := string(line)
				t.history = append(t.history, inputLine)
				req.Response <- inputLine
				line = nil // Clear the line
				t.mu.Lock()
				t.currentLine = "" // Clear currentLine
				t.mu.Unlock()
				stdoutMutex.Lock()
				fmt.Print("\r\n") // Move to the next line
				stdoutMutex.Unlock()
				break
			} else if r == 127 || r == '\b' {
				// Handle backspace
				if len(line) > 0 {
					line = line[:len(line)-1]
					t.mu.Lock()
					t.currentLine = string(line)
					t.mu.Unlock()

					// Erase character from terminal
					stdoutMutex.Lock()
					fmt.Print("\b \b") // Move back, clear, and move back again
					stdoutMutex.Unlock()
				}
			} else if r == 3 {
				// Handle Ctrl+C
				stdoutMutex.Lock()
				fmt.Print("^C\r\n")
				stdoutMutex.Unlock()
				req.Response <- ""
				break
			} else if r == 4 {
				// Handle Ctrl+D (EOF)
				req.Response <- ""
				break
			} else if r == 0x1b { // ESC character
				// Read the next two bytes to identify the escape sequence
				var seq [2]byte
				n, err := os.Stdin.Read(seq[:])
				if err != nil || n < 2 {
					t.PrintMessage("\n\rError reading escape sequence.")
					continue // Skip processing this escape sequence
				}

				if seq[0] == '[' {
					switch seq[1] {
					case 'A': // Up Arrow
						if historyIndex > 0 {
							historyIndex--
							// Retrieve the previous command from history
							historyLine := t.history[historyIndex]
							// Clear the current input line
							t.clearCurrentInput()
							// Update the current line with the history entry
							line = []rune(historyLine)
							t.mu.Lock()
							t.currentLine = historyLine
							t.mu.Unlock()
							// Reprint the prompt and the history line
							stdoutMutex.Lock()
							fmt.Print("\r" + req.Prompt + historyLine)
							stdoutMutex.Unlock()
						}
					case 'B': // Down Arrow
						if historyIndex < len(t.history)-1 {
							historyIndex++
							// Retrieve the next command from history
							historyLine := t.history[historyIndex]
							// Clear the current input line
							t.clearCurrentInput()
							// Update the current line with the history entry
							line = []rune(historyLine)
							t.mu.Lock()
							t.currentLine = historyLine
							t.mu.Unlock()
							// Reprint the prompt and the history line
							stdoutMutex.Lock()
							fmt.Print("\r" + req.Prompt + historyLine)
							stdoutMutex.Unlock()
						} else if historyIndex == len(t.history)-1 {
							historyIndex++
							// Clear the current input line
							t.clearCurrentInput()
							// Reset the current line
							line = nil
							t.mu.Lock()
							t.currentLine = ""
							t.mu.Unlock()
							// Reprint the prompt without any history line
							stdoutMutex.Lock()
							fmt.Print("\r" + req.Prompt)
							stdoutMutex.Unlock()
						}
					default:
						// Handle other escape sequences if necessary
					}
				}
			} else {
				// Add the rune to the line
				line = append(line, r)
				t.mu.Lock()
				t.currentLine = string(line)
				t.mu.Unlock()

				// Echo the character
				stdoutMutex.Lock()
				fmt.Print(string(r))
				stdoutMutex.Unlock()

				// Reset history index since user is typing a new command
				historyIndex = len(t.history)
			}
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

// SetPrompt updates the terminal prompt.
func (t *Terminal) SetPrompt(prompt string) {
	t.prompt = prompt
}

// Close terminates the input manager goroutine and restores terminal state.
func (t *Terminal) Close() {
	close(t.inputRequests)
	term.Restore(int(os.Stdin.Fd()), t.oldState)
}

// PrintMessage prints a message to the terminal in a thread-safe manner.
func (t *Terminal) PrintMessage(message string) {
	t.mu.Lock()
	line := t.currentLine
	t.mu.Unlock()

	t.clearCurrentInput()

	stdoutMutex.Lock()
	defer stdoutMutex.Unlock()
	fmt.Println("\r" + message)
	fmt.Print("\r" + t.prompt + line)
}
