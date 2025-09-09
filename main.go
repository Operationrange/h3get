package main

import (
    "bufio"
    "bytes"
    "context"
    "crypto/md5"
    "crypto/tls"
    "encoding/hex"
    "flag"
    "fmt"
    "io"
    "math/rand"
    "mime"
    "net"
    "net/http"
    "net/url"
    "os"
    "path"
    "path/filepath"
    "strconv"
    "strings"
    "sync"
    "sync/atomic"
    "time"

    "github.com/quic-go/quic-go/http3"
)

//
// --------- Прогресс/статистика ---------
//

type progress struct {
    start      time.Time
    lastPrint  time.Time
    total      int64 // всего записано байт
    size       int64 // Content-Length (или -1)
    filename   string
    printEvery time.Duration

    workers int32 // текущее число потоков (стримов)
}

func (p *progress) add(n int64) { atomic.AddInt64(&p.total, n) }
func (p *progress) setWorkers(n int) {
    atomic.StoreInt32(&p.workers, int32(n))
}
func (p *progress) getWorkers() int {
    return int(atomic.LoadInt32(&p.workers))
}

func (p *progress) loop(ctx context.Context) {
    t := time.NewTicker(p.printEvery)
    defer t.Stop()
    for {
	select {
	case <-ctx.Done():
	    p.print(true)
	    return
	case <-t.C:
	    p.print(false)
	}
    }
}

func (p *progress) print(final bool) {
    now := time.Now()
    elapsed := now.Sub(p.start).Seconds()
    if elapsed <= 0 {
	elapsed = 1e-6
    }
    done := atomic.LoadInt64(&p.total)
    avgSpeed := float64(done) / elapsed // B/s средняя скорость
    streams := p.getWorkers()

    etaStr := ""
    if p.size > 0 && avgSpeed > 1e-6 {
	remain := float64(p.size - done)
	if remain < 0 {
	    remain = 0
	}
	eta := time.Duration(remain/avgSpeed*float64(time.Second)).Truncate(time.Second)
	etaStr = fmt.Sprintf("  ETA %s", eta)
    }

    var line string
    if p.size > 0 {
	pct := float64(done) * 100 / float64(p.size)
	line = fmt.Sprintf("⬇ %s  %s / %s (%.1f%%)  %s/s  streams:%d%s  elapsed %s",
	    p.filename, humanBytes(done), humanBytes(p.size), pct, humanBytes(int64(avgSpeed)), streams,
	    etaStr, time.Duration(elapsed*float64(time.Second)).Truncate(time.Second))
    } else {
	line = fmt.Sprintf("⬇ %s  %s  %s/s  streams:%d  elapsed %s",
	    p.filename, humanBytes(done), humanBytes(int64(avgSpeed)), streams,
	    time.Duration(elapsed*float64(time.Second)).Truncate(time.Second))
    }

    if final {
	fmt.Printf("\r%-140s\n", line)
    } else {
	fmt.Printf("\r%-140s", line)
    }
    p.lastPrint = now
}

func humanBytes(b int64) string {
    const (
	KB = 1024
	MB = 1024 * KB
	GB = 1024 * MB
	TB = 1024 * GB
    )
    switch {
    case b >= TB:
	return fmt.Sprintf("%.2f TB", float64(b)/float64(TB))
    case b >= GB:
	return fmt.Sprintf("%.2f GB", float64(b)/float64(GB))
    case b >= MB:
	return fmt.Sprintf("%.2f MB", float64(b)/float64(MB))
    case b >= KB:
	return fmt.Sprintf("%.2f KB", float64(b)/float64(KB))
    default:
	return fmt.Sprintf("%d B", b)
    }
}

//
// --------- Части и запись по офсету ---------
//

type part struct {
    idx  int
    from int64
    to   int64 // inclusive
}

type job struct {
    p        part
    attempts int
}

type offsetWriter struct {
    f   *os.File
    off int64
    pos int64
}

func (w *offsetWriter) Write(p []byte) (int, error) {
    n, err := w.f.WriteAt(p, w.off+w.pos)
    w.pos += int64(n)
    return n, err
}

type countingWriter struct {
    W   io.Writer
    add func(int)
}

func (cw *countingWriter) Write(p []byte) (int, error) {
    n, err := cw.W.Write(p)
    if n > 0 && cw.add != nil {
	cw.add(n)
    }
    return n, err
}

func defaultFilename(u *url.URL) string {
    base := path.Base(u.Path)
    if base == "." || base == "/" || base == "" {
	return "download"
    }
    return strings.Split(base, "?")[0]
}

// Дробим весь файл на мелкие равные куски (гранулы) по chunk байт.
func makeGranularParts(size int64, chunk int64) []part {
    if chunk < 1 {
	chunk = 1
    }
    n := int(size / chunk)
    if size%chunk != 0 {
	n++
    }
    parts := make([]part, 0, n)
    var from int64
    idx := 0
    for from < size {
	to := from + chunk - 1
	if to >= size {
	    to = size - 1
	}
	parts = append(parts, part{idx: idx, from: from, to: to})
	from = to + 1
	idx++
    }
    return parts
}

//
// --------- Метаданные: финальный URL, имя, размер, поддержка Range ---------
//

type meta struct {
    finalURL     *url.URL
    size         int64
    acceptRanges bool
    cdFilename   string
}

// fetchMeta делает GET c Range: bytes=0-0, следует редиректам,
// и извлекает финальный URL, размер, поддержку range и имя из Content-Disposition.
func fetchMeta(ctx context.Context, client *http.Client, rawURL string) (*meta, error) {
    req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
    if err != nil {
	return nil, err
    }
    req.Header.Set("Range", "bytes=0-0")
    req.Header.Set("Alt-Svc", "h3=\":443\"")
    req.Header.Set("User-Agent", "h3get/auto (+quic-go)")

    resp, err := client.Do(req)
    if err != nil {
	return nil, err
    }
    defer resp.Body.Close()

    m := &meta{finalURL: resp.Request.URL, size: -1}

    // Имя из Content-Disposition (если есть)
    if cd := resp.Header.Get("Content-Disposition"); cd != "" {
	if _, params, err := mime.ParseMediaType(cd); err == nil {
	    if v, ok := params["filename*"]; ok {
		if i := strings.Index(v, "''"); i >= 0 && i+2 < len(v) {
		    raw := v[i+2:]
		    if dec, derr := url.QueryUnescape(raw); derr == nil && dec != "" {
			m.cdFilename = dec
		    }
		}
	    }
	    if m.cdFilename == "" {
		if v, ok := params["filename"]; ok && v != "" {
		    m.cdFilename = v
		}
	    }
	}
    }

    switch resp.StatusCode {
    case http.StatusPartialContent: // 206
	if cr := resp.Header.Get("Content-Range"); cr != "" {
	    if slash := strings.LastIndex(cr, "/"); slash >= 0 && slash+1 < len(cr) {
		if total, err := strconv.ParseInt(cr[slash+1:], 10, 64); err == nil && total > 0 {
		    m.size = total
		}
	    }
	}
	m.acceptRanges = true
    case http.StatusOK: // 200
	if cl := resp.Header.Get("Content-Length"); cl != "" {
	    if v, err := strconv.ParseInt(cl, 10, 64); err == nil && v > 0 {
		m.size = v
	    }
	}
	m.acceptRanges = strings.EqualFold(resp.Header.Get("Accept-Ranges"), "bytes")
    }
    return m, nil
}

//
// --------- HTTP/3 helpers ---------
//

func singleDownload(ctx context.Context, client *http.Client, rawURL string, out *os.File, p *progress) error {
    req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
    if err != nil {
	return err
    }
    req.Header.Set("Alt-Svc", "h3=\":443\"")
    req.Header.Set("User-Agent", "h3get/auto (+quic-go)")

    resp, err := client.Do(req)
    if err != nil {
	return err
    }
    defer resp.Body.Close()

    if resp.StatusCode < 200 || resp.StatusCode >= 300 {
	return fmt.Errorf("bad status: %s", resp.Status)
    }
    if resp.ContentLength > 0 {
	p.size = resp.ContentLength
    }

    bw := bufio.NewWriterSize(out, 1<<20)
    defer bw.Flush()

    _, err = io.CopyBuffer(&countingWriter{W: bw, add: func(n int) { p.add(int64(n)) }},
	resp.Body, make([]byte, 512*1024))
    return err
}

//
// --------- MD5 ---------
//

func downloadMD5(ctx context.Context, client *http.Client, baseURL string, savePath string) (string, error) {
    md5URL := baseURL + ".md5"
    req, err := http.NewRequestWithContext(ctx, http.MethodGet, md5URL, nil)
    if err != nil {
	return "", err
    }
    req.Header.Set("Alt-Svc", "h3=\":443\"")
    req.Header.Set("User-Agent", "h3get/auto (+quic-go)")

    resp, err := client.Do(req)
    if err != nil {
	return "", err
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
	return "", fmt.Errorf("md5 not available: %s", resp.Status)
    }

    var buf bytes.Buffer
    if _, err := io.Copy(&buf, resp.Body); err != nil {
	return "", err
    }

    if err := os.WriteFile(savePath, buf.Bytes(), 0o644); err != nil {
	return "", fmt.Errorf("write md5 file: %w", err)
    }

    sum := parseMD5Sum(buf.String())
    if sum == "" {
	return "", fmt.Errorf("cannot parse md5 from %s", md5URL)
    }
    return sum, nil
}

func parseMD5Sum(s string) string {
    s = strings.TrimSpace(s)
    isHex := func(r rune) bool {
	return (r >= '0' && r <= '9') ||
	    (r >= 'a' && r <= 'f') ||
	    (r >= 'A' && r <= 'F')
    }
    for i := 0; i+32 <= len(s); i++ {
	sub := s[i : i+32]
	ok := true
	for _, r := range sub {
	    if !isHex(r) {
		ok = false
		break
	    }
	}
	if ok {
	    return strings.ToLower(sub)
	}
    }
    return ""
}

func computeFileMD5(path string) (string, error) {
    f, err := os.Open(path)
    if err != nil {
	return "", err
    }
    defer f.Close()

    h := md5.New()
    buf := make([]byte, 1<<20)
    for {
	n, rerr := f.Read(buf)
	if n > 0 {
	    if _, werr := h.Write(buf[:n]); werr != nil {
		return "", werr
	    }
	}
	if rerr == io.EOF {
	    break
	}
	if rerr != nil {
	    return "", rerr
	}
    }
    return hex.EncodeToString(h.Sum(nil)), nil
}

//
// --------- Retry policy ---------
//

func isRetryableHTTP(status int) bool {
    return status == 408 || status == 429 || (status >= 500 && status <= 599)
}

func isNetErrRetryable(err error) bool {
    if err == nil {
	return false
    }
    var ne net.Error
    if errorsAs(err, &ne) && (ne.Timeout() || ne.Temporary()) {
	return true
    }
    msg := strings.ToLower(err.Error())
    if strings.Contains(msg, "timeout") ||
	strings.Contains(msg, "no recent network activity") ||
	strings.Contains(msg, "connection reset") ||
	strings.Contains(msg, "broken pipe") ||
	strings.Contains(msg, "stream closed") ||
	strings.Contains(msg, "use of closed network connection") {
	return true
    }
    return false
}

// минималистичный wrapper для errors.As под net.Error (без импорта errors)
func errorsAs(err error, target interface{}) bool {
    switch t := target.(type) {
    case *net.Error:
	if ne, ok := err.(net.Error); ok {
	    *t = ne
	    return true
	}
    }
    return false
}

//
// --------- main ---------
//

func main() {
    // немного энтропии для джиттера бэкоффа
    rand.Seed(time.Now().UnixNano())

    // Флаги
    outName := flag.String("o", "", "output file name (optional)")
    outDir := flag.String("out-dir", "", "output directory (will be created if missing)")
    insecure := flag.Bool("insecure", false, "skip TLS verification (NOT recommended)")
    timeout := flag.Duration("timeout", 0, "overall timeout (e.g. 2m). 0 = no timeout")

    minParallel := flag.Int("min-parallel", 16, "minimum number of parallel streams (default 16)")
    maxParallel := flag.Int("max-parallel", 1024, "maximum number of parallel streams (cap at 1024)")
    partSizeStr := flag.String("part-size", "8MiB", "granule size (e.g. 8MiB, 16MB, 1048576)")

    auto := flag.Bool("auto", true, "enable adaptive concurrency growth")
    autoInterval := flag.Duration("auto-interval", 1*time.Second, "rate sampling interval (default 1s)")
    autoThreshold := flag.Float64("auto-threshold", 0.05, "relative gain to add a worker (e.g. 0.05 = +5%)")

    skipMD5 := flag.Bool("no-md5", false, "do not auto-download and verify .md5 file")

    retries := flag.Int("retries", 5, "max retry attempts per chunk on transient errors")
    retryBase := flag.Duration("retry-base", 500*time.Millisecond, "base backoff for retries")
    retryMax := flag.Duration("retry-max", 10*time.Second, "max backoff for retries")

    flag.Parse()

    if flag.NArg() != 1 {
	fmt.Fprintf(os.Stderr, "usage: %s [-o out.bin] [-out-dir DIR] [--min-parallel 16] [--max-parallel 1024] [--part-size 8MiB] [--auto] [--auto-interval 1s] [--auto-threshold 0.05] [--no-md5] [--retries 5] [--retry-base 500ms] [--retry-max 10s] [--insecure] [--timeout 2m] https://host/path/file\n", os.Args[0])
	os.Exit(2)
    }

    origRawURL := flag.Arg(0)
    origU, err := url.Parse(origRawURL)
    if err != nil {
	fmt.Fprintf(os.Stderr, "invalid URL: %v\n", err)
	os.Exit(1)
    }
    if origU.Scheme != "https" {
	fmt.Fprintf(os.Stderr, "only https:// URLs are supported for HTTP/3\n")
	os.Exit(1)
    }

    // Контекст
    baseCtx := context.Background()
    if *timeout > 0 {
	var cancel context.CancelFunc
	baseCtx, cancel = context.WithTimeout(baseCtx, *timeout)
	defer cancel()
    }
    ctx, cancelAll := context.WithCancel(baseCtx)
    defer cancelAll()

    // HTTP/3 транспорт + клиент
    tr := &http3.Transport{
	TLSClientConfig: &tls.Config{
	    InsecureSkipVerify: *insecure, //nolint:gosec
	    NextProtos:         []string{"h3"},
	},
    }
    defer tr.Close()
    client := &http.Client{Transport: tr}

    // Метаданные
    m, err := fetchMeta(ctx, client, origU.String())
    if err != nil {
	m = &meta{finalURL: origU, size: -1, acceptRanges: false}
    }
    useURL := m.finalURL
    size := m.size
    acceptRanges := m.acceptRanges

    // Имя файла
    filename := *outName
    if filename == "" {
	if m.cdFilename != "" {
	    filename = m.cdFilename
	} else {
	    filename = defaultFilename(useURL)
	}
    }
    if *outDir != "" {
	if err := os.MkdirAll(*outDir, 0o755); err != nil {
	    fmt.Fprintf(os.Stderr, "cannot create out-dir: %v\n", err)
	    os.Exit(1)
	}
	if *outName != "" && !filepath.IsAbs(*outName) && !strings.ContainsAny(*outName, "/\\") {
	    filename = filepath.Join(*outDir, *outName)
	} else if *outName == "" {
	    filename = filepath.Join(*outDir, filename)
	}
    } else if *outName != "" {
	filename = *outName
    }

    chunkSize, perr := parseSize(*partSizeStr)
    if perr != nil || chunkSize < 1 {
	fmt.Fprintf(os.Stderr, "invalid -part-size: %q\n", *partSizeStr)
	os.Exit(1)
    }
    if *minParallel < 1 {
	*minParallel = 1
    }
    if *maxParallel > 1024 {
	*maxParallel = 1024
    }
    if *maxParallel < *minParallel {
	*maxParallel = *minParallel
    }

    // Файл
    if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
	fmt.Fprintf(os.Stderr, "cannot create output dir structure: %v\n", err)
	os.Exit(1)
    }
    out, err := os.Create(filename)
    if err != nil {
	fmt.Fprintf(os.Stderr, "open output file: %v\n", err)
	os.Exit(1)
    }
    defer func() {
	out.Close()
	fmt.Println()
    }()

    // Прогресс
    var pw progress
    pw.start = time.Now()
    pw.lastPrint = time.Now()
    pw.size = size
    pw.filename = filename
    pw.printEvery = 200 * time.Millisecond
    pw.setWorkers(0)

    progressCtx, progressCancel := context.WithCancel(ctx)
    defer progressCancel()
    go pw.loop(progressCtx)

    // Фолбэк: одиночная закачка
    if size <= 0 || !acceptRanges {
	if !acceptRanges {
	    fmt.Fprintf(os.Stderr, "info: server may not allow ranges; falling back to single-stream download.\n")
	}
	pw.setWorkers(1)
	if err := singleDownload(ctx, client, useURL.String(), out, &pw); err != nil {
	    pw.print(true)
	    fmt.Fprintf(os.Stderr, "download error: %v\n", err)
	    os.Exit(1)
	}
	progressCancel()
	pw.print(true)
	fmt.Printf("Saved to: %s\n", filename)
	if !*skipMD5 {
	    verifyMD5OrWarn(ctx, client, useURL.String(), filename)
	}
	return
    }

    // Параллельная закачка с ретраями

    parts := makeGranularParts(size, chunkSize)
    if err := out.Truncate(size); err != nil {
	fmt.Fprintf(os.Stderr, "preallocate file failed: %v\n", err)
	os.Exit(1)
    }

    // Очередь задач (не закрываем; ретраи перекидывают обратно)
    jobs := make(chan job, 4*(*maxParallel))

    // Группы синхронизации
    var wgParts sync.WaitGroup
    wgParts.Add(len(parts))

    // Контроллер скоростей
    var (
	lastBytes      int64 = 0
	bestRate             = 0.0
	warmupDone           = false
	lastTickTime         = time.Now()
    )
    ticker := time.NewTicker(*autoInterval)
    defer ticker.Stop()

    ctrlCtx, ctrlCancel := context.WithCancel(ctx)
    defer ctrlCancel()

    workersStarted := 0
    startWorker := func(id int) {
	workersStarted++
	pw.setWorkers(workersStarted)
	go func(workerID int) {
	    buf := make([]byte, 512*1024)
	    for {
		select {
		case <-ctx.Done():
		    return
		case j := <-jobs:
		    // обработка одного куска с ретраями
		    for {
			select {
			case <-ctx.Done():
			    return
			default:
			}

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, useURL.String(), nil)
			if err != nil {
			    // синтетическая ошибка для ретрая
			} else {
			    req.Header.Set("Alt-Svc", "h3=\":443\"")
			    req.Header.Set("User-Agent", "h3get/auto (+quic-go)")
			    req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", j.p.from, j.p.to))

			    resp, cerr := client.Do(req)
			    if cerr != nil {
				err = cerr
			    } else {
				// статус
				if !(resp.StatusCode == http.StatusPartialContent || resp.StatusCode == http.StatusOK) {
				    if isRetryableHTTP(resp.StatusCode) {
					err = fmt.Errorf("status %s", resp.Status)
				    } else {
					resp.Body.Close()
					fmt.Fprintf(os.Stderr, "fatal: worker %d part %d unexpected status: %s\n", workerID, j.p.idx, resp.Status)
					cancelAll()
					return
				    }
				} else {
				    bw := bufio.NewWriterSize(&offsetWriter{f: out, off: j.p.from}, 1<<20)
				    _, err = io.CopyBuffer(&countingWriter{W: bw, add: func(n int) { pw.add(int64(n)) }},
					resp.Body, buf)
				    flushErr := bw.Flush()
				    closeErr := resp.Body.Close()
				    if err == nil && flushErr != nil {
					err = flushErr
				    }
				    if err == nil && closeErr != nil {
					err = closeErr
				    }
				    if err == nil {
					// успех
					wgParts.Done()
					break
				    }
				}
			    }
			}

			// ошибка: решаем, ретраить ли
			retryable := isNetErrRetryable(err) || strings.Contains(strings.ToLower(err.Error()), "eof") || strings.Contains(err.Error(), "status")
			if j.attempts >= *retries || !retryable {
			    fmt.Fprintf(os.Stderr, "part %d failed permanently after %d attempts: %v\n", j.p.idx, j.attempts, err)
			    cancelAll()
			    return
			}

			// бэкофф с джиттером
			backoff := time.Duration(float64(*retryBase) * pow2(j.attempts))
			if backoff > *retryMax {
			    backoff = *retryMax
			}
			jitter := time.Duration((rand.Float64()*0.4 - 0.2) * float64(backoff))
			backoff = backoff + jitter
			if backoff < 0 {
			    backoff = 100 * time.Millisecond
			}
			fmt.Fprintf(os.Stderr, "retry part %d (attempt %d): %v, backoff %s\n", j.p.idx, j.attempts+1, err, backoff)

			timer := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
			    timer.Stop()
			    return
			case <-timer.C:
			}
			j.attempts++
			// отдадим обратно в очередь для любого воркера
			select {
			case <-ctx.Done():
			    return
			case jobs <- j:
			    // передали на повтор — выходим из внутреннего цикла
			    goto nextJob
			}
		    }
		nextJob:
		}
	    }
	}(id)
    }

    // Стартуем минимум потоков
    for i := 0; i < *minParallel; i++ {
	startWorker(i)
    }

    // Продьюсер частей — отдельно, чтобы не блокировать на большом файле
    go func() {
	for _, p := range parts {
	    select {
	    case <-ctx.Done():
		return
	    case jobs <- job{p: p, attempts: 0}:
	    }
	}
    }()

    // Контроллер скоростей: растим число потоков до max-parallel, пока есть заметный прирост
    go func() {
	for {
	    select {
	    case <-ctrlCtx.Done():
		return
	    case <-ticker.C:
		now := time.Now()
		elapsed := now.Sub(lastTickTime).Seconds()
		if elapsed <= 0 {
		    elapsed = (*autoInterval).Seconds()
		}
		curBytes := atomic.LoadInt64(&pw.total)
		delta := curBytes - lastBytes
		lastBytes = curBytes
		lastTickTime = now

		currentRate := float64(delta) / elapsed // B/s

		if !*auto {
		    continue
		}
		if !warmupDone {
		    bestRate = currentRate
		    warmupDone = true
		    continue
		}
		threshold := bestRate * (1.0 + *autoThreshold)
		if currentRate > threshold && workersStarted < *maxParallel {
		    bestRate = currentRate
		    startWorker(workersStarted)
		    pw.setWorkers(workersStarted)
		}
	    }
	}
    }()

    // Ждём завершения всех частей
    wgParts.Wait()

    // Останавливаем всё
    cancelAll()
    progressCancel()
    pw.print(true)

    fmt.Printf("Saved to: %s\n", filename)

    // MD5-проверка
    if !*skipMD5 {
	verifyMD5OrWarn(context.Background(), client, useURL.String(), filename)
    }
}

//
// --------- Вспомогательное ---------
//

func parseSize(s string) (int64, error) {
    s = strings.TrimSpace(strings.ToUpper(s))
    if s == "" {
	return 0, fmt.Errorf("empty")
    }
    if allDigits(s) {
	v, err := strconv.ParseInt(s, 10, 64)
	return v, err
    }
    type unit struct {
	suf string
	mul int64
    }
    units := []unit{
	{"KIB", 1024},
	{"MIB", 1024 * 1024},
	{"GIB", 1024 * 1024 * 1024},
	{"KB", 1000},
	{"MB", 1000 * 1000},
	{"GB", 1000 * 1000 * 1000},
    }
    for _, u := range units {
	if strings.HasSuffix(s, u.suf) {
	    num := strings.TrimSuffix(s, u.suf)
	    num = strings.TrimSpace(num)
	    v, err := strconv.ParseFloat(num, 64)
	    if err != nil {
		return 0, err
	    }
	    return int64(v * float64(u.mul)), nil
	}
    }
    if strings.HasSuffix(s, "K") || strings.HasSuffix(s, "M") || strings.HasSuffix(s, "G") {
	base := s[:len(s)-1]
	mult := int64(1)
	switch s[len(s)-1] {
	case 'K':
	    mult = 1024
	case 'M':
	    mult = 1024 * 1024
	case 'G':
	    mult = 1024 * 1024 * 1024
	}
	v, err := strconv.ParseFloat(base, 64)
	if err != nil {
	    return 0, err
	}
	return int64(v * float64(mult)), nil
    }
    return 0, fmt.Errorf("unknown size format: %q", s)
}

func allDigits(s string) bool {
    for _, r := range s {
	if r < '0' || r > '9' {
	    return false
	}
    }
    return true
}

func pow2(n int) float64 {
    if n <= 0 {
	return 1
    }
    return float64(uint64(1) << uint(n))
}

//
// --------- MD5 helper runner ---------
//

func verifyMD5OrWarn(ctx context.Context, client *http.Client, srcURL, localPath string) {
    md5Path := localPath + ".md5"
    expected, err := downloadMD5(ctx, client, srcURL, md5Path)
    if err != nil {
	fmt.Fprintf(os.Stderr, "warn: cannot fetch/parse .md5 (%v); skipping verification.\n", err)
	return
    }
    actual, err := computeFileMD5(localPath)
    if err != nil {
	fmt.Fprintf(os.Stderr, "warn: cannot compute local md5 (%v); skipping verification.\n", err)
	return
    }
    if strings.EqualFold(expected, actual) {
	fmt.Printf("MD5 OK: %s\n", actual)
    } else {
	fmt.Fprintf(os.Stderr, "ERROR: MD5 mismatch!\n  expected: %s\n  actual:   %s\n", expected, actual)
	os.Exit(1)
    }
}
