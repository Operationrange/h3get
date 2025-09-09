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
    "net/http"
    "net/url"
    "os"
    "path"
    "path/filepath"
    "strconv"
    "strings"
    "sync/atomic"
    "time"

    "github.com/quic-go/quic-go/http3"
    "golang.org/x/sync/errgroup"
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
// --------- HTTP/3 вспомогательное ---------
//

// probeHEAD делает HEAD, возвращая размер, признак диапазонов и ФИНАЛЬНЫЙ URL после редиректов.
func probeHEAD(ctx context.Context, client *http.Client, rawURL string) (int64, bool, *url.URL, error) {
    req, err := http.NewRequestWithContext(ctx, http.MethodHead, rawURL, nil)
    if err != nil {
	return -1, false, nil, err
    }
    req.Header.Set("Alt-Svc", "h3=\":443\"")
    req.Header.Set("User-Agent", "h3get/auto (+quic-go)")
    resp, err := client.Do(req)
    if err != nil {
	return -1, false, nil, err
    }
    defer resp.Body.Close()

    finalURL := resp.Request.URL

    var size int64 = -1
    if cl := resp.Header.Get("Content-Length"); cl != "" {
	if v, err := strconv.ParseInt(cl, 10, 64); err == nil && v > 0 {
	    size = v
	}
    }
    acceptRanges := strings.EqualFold(resp.Header.Get("Accept-Ranges"), "bytes")
    return size, acceptRanges, finalURL, nil
}

// probeRange пробует GET bytes=0-0 и возвращает, поддерживаются ли диапазоны, и финальный URL.
func probeRange(ctx context.Context, client *http.Client, rawURL string) (bool, *url.URL) {
    req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
    if err != nil {
	return false, nil
    }
    req.Header.Set("Range", "bytes=0-0")
    req.Header.Set("Alt-Svc", "h3=\":443\"")
    req.Header.Set("User-Agent", "h3get/auto (+quic-go)")
    resp, err := client.Do(req)
    if err != nil {
	return false, nil
    }
    defer resp.Body.Close()
    return resp.StatusCode == http.StatusPartialContent, resp.Request.URL
}

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
// --------- MD5: загрузка, парсинг, вычисление, проверка ---------
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

    // Сохраним .md5 рядом с файлом
    if err := os.WriteFile(savePath, buf.Bytes(), 0o644); err != nil {
	return "", fmt.Errorf("write md5 file: %w", err)
    }

    // Распарсим ожидаемый хэш
    sum := parseMD5Sum(buf.String())
    if sum == "" {
	return "", fmt.Errorf("cannot parse md5 from %s", md5URL)
    }
    return sum, nil
}

// Поддерживаем форматы:
//   <hex32>
//   <hex32>  filename
//   MD5 (filename) = <hex32>
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
    buf := make([]byte, 1<<20) // 1 MiB
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
// --------- main: адаптивное масштабирование потоков + MD5-проверка + имя по редиректу ---------
//

func main() {
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

    flag.Parse()

    if flag.NArg() != 1 {
	fmt.Fprintf(os.Stderr, "usage: %s [-o out.bin] [-out-dir DIR] [--min-parallel 16] [--max-parallel 1024] [--part-size 8MiB] [--auto] [--auto-interval 1s] [--auto-threshold 0.05] [--no-md5] [--insecure] [--timeout 2m] https://host/path/file\n", os.Args[0])
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
    ctx := context.Background()
    if *timeout > 0 {
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(ctx, *timeout)
	defer cancel()
    }

    // HTTP/3 транспорт + клиент
    tr := &http3.Transport{
	TLSClientConfig: &tls.Config{
	    InsecureSkipVerify: *insecure, //nolint:gosec
	    NextProtos:         []string{"h3"},
	},
    }
    defer tr.Close()
    client := &http.Client{Transport: tr}

    // HEAD + получаем финальный URL
    size, acceptRanges, finalURL, headErr := probeHEAD(ctx, client, origU.String())
    useURL := origU
    if headErr == nil && finalURL != nil {
	useURL = finalURL
    }
    // Если HEAD не дал диапазоны, попробуем Range 0-0 — тоже получим finalURL на всякий случай
    if !acceptRanges && size > 0 {
	if ok, rFinal := probeRange(ctx, client, useURL.String()); ok {
	    acceptRanges = true
	    if rFinal != nil {
		useURL = rFinal
	    }
	}
    }

    // Имя файла / директория — если -o не задан, берём имя из ФИНАЛЬНОГО URL
    filename := *outName
    if filename == "" {
	filename = defaultFilename(useURL)
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

    // Размер части
    chunkSize, perr := parseSize(*partSizeStr)
    if perr != nil || chunkSize < 1 {
	fmt.Fprintf(os.Stderr, "invalid -part-size: %q\n", *partSizeStr)
	os.Exit(1)
    }

    // Нормализуем границы потоков
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
	    fmt.Fprintf(os.Stderr, "info: server does not advertise/allow ranges; falling back to single-stream download.\n")
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
	// MD5-проверка после одиночной загрузки
	if !*skipMD5 {
	    verifyMD5OrWarn(ctx, client, useURL.String(), filename)
	}
	return
    }

    // Параллельная закачка с адаптивным ростом потоков

    // Список мелких частей (гранул)
    parts := makeGranularParts(size, chunkSize)

    // Преаллокация файла
    if err := out.Truncate(size); err != nil {
	fmt.Fprintf(os.Stderr, "preallocate file failed: %v\n", err)
	os.Exit(1)
    }

    // Очередь задач
    jobs := make(chan part, 2*(*maxParallel))
    go func() {
	for _, p := range parts {
	    jobs <- p
	}
	close(jobs)
    }()

    // errgroup для воркеров (отменит всех при ошибке одного)
    eg, gctx := errgroup.WithContext(ctx)

    // Старт воркера (один HTTP/3 запрос = один стрим)
    startWorker := func(id int) {
	eg.Go(func() error {
	    for {
		select {
		case <-gctx.Done():
		    return gctx.Err()
		case p, ok := <-jobs:
		    if !ok {
			return nil
		    }
		    req, err := http.NewRequestWithContext(gctx, http.MethodGet, useURL.String(), nil)
		    if err != nil {
			return err
		    }
		    req.Header.Set("Alt-Svc", "h3=\":443\"")
		    req.Header.Set("User-Agent", "h3get/auto (+quic-go)")
		    req.Header.Set("Range", fmt.Sprintf("bytes=%d-%d", p.from, p.to))

		    resp, err := client.Do(req)
		    if err != nil {
			return fmt.Errorf("worker %d part %d: %w", id, p.idx, err)
		    }
		    if resp.StatusCode != http.StatusPartialContent && resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return fmt.Errorf("worker %d part %d unexpected status: %s", id, p.idx, resp.Status)
		    }

		    bw := bufio.NewWriterSize(&offsetWriter{f: out, off: p.from}, 1<<20)
		    _, err = io.CopyBuffer(&countingWriter{W: bw, add: func(n int) { pw.add(int64(n)) }},
			resp.Body, make([]byte, 512*1024))
		    flushErr := bw.Flush()
		    closeErr := resp.Body.Close()
		    if err != nil {
			return fmt.Errorf("worker %d part %d copy: %w", id, p.idx, err)
		    }
		    if flushErr != nil {
			return fmt.Errorf("worker %d flush: %w", id, flushErr)
		    }
		    if closeErr != nil {
			return fmt.Errorf("worker %d close body: %w", id, closeErr)
		    }
		}
	    }
	})
    }

    // Запускаем минимум потоков сразу
    workersStarted := 0
    for i := 0; i < *minParallel; i++ {
	startWorker(workersStarted)
	workersStarted++
    }
    pw.setWorkers(workersStarted)

    // Контроллер скоростей: растим число потоков до max-parallel, пока есть заметный прирост
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

		// первая метка — инициализация bestRate
		if !warmupDone {
		    bestRate = currentRate
		    warmupDone = true
		    continue
		}

		// Рост при улучшении > threshold
		threshold := bestRate * (1.0 + *autoThreshold)
		if currentRate > threshold && workersStarted < *maxParallel {
		    bestRate = currentRate
		    startWorker(workersStarted)
		    workersStarted++
		    pw.setWorkers(workersStarted)
		}
	    }
	}
    }()

    // Ожидаем завершения всех задач
    err = eg.Wait()
    // Останавливаем контроллер и прогресс
    ctrlCancel()
    progressCancel()
    pw.print(true)

    if err != nil {
	fmt.Fprintf(os.Stderr, "download error: %v\n", err)
	os.Exit(1)
    }

    fmt.Printf("Saved to: %s\n", filename)

    // MD5-проверка после параллельной загрузки
    if !*skipMD5 {
	verifyMD5OrWarn(ctx, client, useURL.String(), filename)
    }
}

//
// --------- Парсинг размеров ---------
//

func parseSize(s string) (int64, error) {
    s = strings.TrimSpace(strings.ToUpper(s))
    if s == "" {
	return 0, fmt.Errorf("empty")
    }
    // чистое число — байты
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
    // "8K", "16M", "1.5G"
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
