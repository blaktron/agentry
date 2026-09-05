package scan

// detection is one located hit a stage records before it decides what the
// hit means: the file and line, nothing else.
type detection struct {
	file string
	line int
}
