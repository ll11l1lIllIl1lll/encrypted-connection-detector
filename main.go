package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"net"
)

const (
    socksVersion = 5
    noAuth       = 0
    cmdConnect   = 1
    atypIPv4     = 1
    atypDomain   = 3
    atypIPv6     = 4
)

var spamLimiter = 0

func main() {
    listenPort := flag.String("listen", "1080", "port to listen on")
    forwardTarget := flag.String("forward", "", "target address to forward to (host:port)")
    flag.Parse()

    listener, err := net.Listen("tcp", ":"+*listenPort)
    if err != nil {
        log.Fatalf("Failed to listen on port %s: %v", *listenPort, err)
    }
    defer listener.Close()
    log.Printf("Listening on :%s", *listenPort)

    for {
        conn, err := listener.Accept()
        if err != nil {
            log.Printf("Failed to accept connection: %v", err)
            continue
        }
        if *forwardTarget != "" {
            go handlePortForwarding(conn, *forwardTarget)
        } else {
            go handleSOCKS5Connection(conn)
        }
    }
}

func handlePortForwarding(conn net.Conn, target string) {
    defer conn.Close()

    destConn, err := net.Dial("tcp", target)
    if err != nil {
        log.Printf("Failed to connect to target %s: %v", target, err)
        return
    }
    defer destConn.Close()

    tlsDetected := false
    go transferData(conn, destConn, "client to server", &tlsDetected)
    transferData(destConn, conn, "server to client", &tlsDetected)
}

func handleSOCKS5Connection(conn net.Conn) {
    defer conn.Close()

    if err := handleSOCKS5Handshake(conn); err != nil {
        log.Printf("Failed to handle handshake: %v", err)
        return
    }

    destConn, err := handleSOCKS5Request(conn)
    if err != nil {
        log.Printf("Failed to handle request: %v", err)
        return
    }
    defer destConn.Close()

    tlsDetected := false
    go transferData(conn, destConn, "client to server", &tlsDetected)
    transferData(destConn, conn, "server to client", &tlsDetected)
}

func handleSOCKS5Handshake(conn net.Conn) error {
    buf := make([]byte, 2)
    if _, err := io.ReadFull(conn, buf); err != nil {
        return fmt.Errorf("failed to read version and nmethods: %v", err)
    }
    if buf[0] != socksVersion {
        return fmt.Errorf("unsupported SOCKS version: %v", buf[0])
    }
    nmethods := buf[1]

    methods := make([]byte, nmethods)
    if _, err := io.ReadFull(conn, methods); err != nil {
        return fmt.Errorf("failed to read methods: %v", err)
    }

    response := []byte{socksVersion, noAuth}
    if _, err := conn.Write(response); err != nil {
        return fmt.Errorf("failed to write handshake response: %v", err)
    }
    return nil
}

func handleSOCKS5Request(conn net.Conn) (net.Conn, error) {
    buf := make([]byte, 4)
    if _, err := io.ReadFull(conn, buf); err != nil {
        return nil, fmt.Errorf("failed to read request: %v", err)
    }
    if buf[0] != socksVersion {
        return nil, fmt.Errorf("unsupported SOCKS version: %v", buf[0])
    }
    if buf[1] != cmdConnect {
        return nil, fmt.Errorf("unsupported command: %v", buf[1])
    }

    var destAddr string
    switch buf[3] {
    case atypIPv4:
        addr := make([]byte, 4)
        if _, err := io.ReadFull(conn, addr); err != nil {
            return nil, fmt.Errorf("failed to read IPv4 address: %v", err)
        }
        port := make([]byte, 2)
        if _, err := io.ReadFull(conn, port); err != nil {
            return nil, fmt.Errorf("failed to read port: %v", err)
        }
        destAddr = fmt.Sprintf("%s:%d", net.IP(addr).String(), binary.BigEndian.Uint16(port))
    case atypDomain:
        domainLen := make([]byte, 1)
        if _, err := io.ReadFull(conn, domainLen); err != nil {
            return nil, fmt.Errorf("failed to read domain length: %v", err)
        }
        domain := make([]byte, domainLen[0])
        if _, err := io.ReadFull(conn, domain); err != nil {
            return nil, fmt.Errorf("failed to read domain: %v", err)
        }
        port := make([]byte, 2)
        if _, err := io.ReadFull(conn, port); err != nil {
            return nil, fmt.Errorf("failed to read port: %v", err)
        }
        destAddr = fmt.Sprintf("%s:%d", string(domain), binary.BigEndian.Uint16(port))
    case atypIPv6:
        addr := make([]byte, 16)
        if _, err := io.ReadFull(conn, addr); err != nil {
            return nil, fmt.Errorf("failed to read IPv6 address: %v", err)
        }
        port := make([]byte, 2)
        if _, err := io.ReadFull(conn, port); err != nil {
            return nil, fmt.Errorf("failed to read port: %v", err)
        }
        destAddr = fmt.Sprintf("[%s]:%d", net.IP(addr).String(), binary.BigEndian.Uint16(port))
    default:
        return nil, fmt.Errorf("unsupported address type: %v", buf[3])
    }

    destConn, err := net.Dial("tcp", destAddr)
    if err != nil {
        response := []byte{socksVersion, 5, 0, 1, 0, 0, 0, 0, 0, 0} // Connection refused
        conn.Write(response)
        return nil, fmt.Errorf("failed to connect to destination: %v", err)
    }

    response := []byte{socksVersion, 0, 0, 1, 0, 0, 0, 0, 0, 0} // Success
    conn.Write(response)

    return destConn, nil
}

func transferData(src, dst net.Conn, direction string, tlsDetected *bool) {
    reader := bufio.NewReader(src)
    writer := bufio.NewWriter(dst)

    buf := make([]byte, 1024)
    for {
        n, err := reader.Read(buf)
        if err != nil {
            if err != io.EOF {
                log.Printf("Error reading data: %v", err)
            }
            break
        }

        // Detect and skip TLS traffic
        if !*tlsDetected && isTLSClientHello(buf[:n]) {
            log.Printf("TLS connection detected, skipping analysis")
            *tlsDetected = true
        }

        // Only analyze non-TLS traffic
        if (!*tlsDetected) && len(buf) > 0 {
            analyzeTraffic(buf[:n], direction)
        }

        if _, err := writer.Write(buf[:n]); err != nil {
            log.Printf("Error writing data: %v", err)
            break
        }
        writer.Flush()
    }
}

func isTLSClientHello(data []byte) bool {
    if len(data) < 5 {
        return false
    }
    return data[0] == 0x16 && data[1] == 0x03 && data[2] <= 0x03 && data[5] == 0x01
}

func analyzeTraffic(data []byte, direction string) {
    frequencies := calculateByteFrequencies(data)
    isEnc, v, r, e, er, _, sc := checkEncryption(frequencies, len(data), data)
    if isEnc {
        log.Printf("\033[0;31m!! Data in %s is possibly encrypted, variance=%f, ratio=%f, entropy=%f, entropyRatio=%f, score=%f\033[0m", direction, v, r, e, er, sc)
    } else {
        log.Printf("Data in %s is possibly unencrypted, variance=%f, ratio=%f, entropy=%f, entropyRatio=%f, score=%f", direction, v, r, e, er, sc)
	spamLimiter = spamLimiter % 11
    }
}

func calculateByteFrequencies(data []byte) []int {
    frequencies := make([]int, 256)
    for _, b := range data {
        frequencies[b]++
    }
    return frequencies
}

func calculateEntropy(data []byte) float64 {
    frequencies := calculateByteFrequencies(data)
    var entropy float64
    total := len(data)

    for _, freq := range frequencies {
        if freq > 0 {
            p := float64(freq) / float64(total)
            entropy -= p * math.Log2(p)
        }
    }
    return entropy
}

func checkEncryption(frequencies []int, dataLength int, data []byte) (bool, float64, float64, float64, float64, float64, float64) {
    var nonZeroFrequencies []float64
    for _, freq := range frequencies {
        if freq > 0 {
            nonZeroFrequencies = append(nonZeroFrequencies, float64(freq))
        }
    }

    if len(nonZeroFrequencies) == 0 {
        return false, 0, 0, 0, 0, 0, 0
    }

    variance := calculateVariance(nonZeroFrequencies)
    ratio := variance / float64(dataLength)

    entropy := calculateEntropy(data)
    entropyRatio := entropy / float64(dataLength)

    binaryRatio := calculateBinaryRatio(data)

    if variance == 0 || ratio == 0 || entropy == 0 || entropyRatio == 0 {
        return false, variance, ratio, entropy, entropyRatio, binaryRatio, 0
    }

    varianceWeight := 0.7
    ratioWeight := 0.1
    entropyRatioWeight := 0.1
    entropyWeight := 0.3

    varianceScore := 1 / (1 + math.Exp(-(3-variance)/0.5))
    ratioScore := 1 / (1 + math.Exp(-(0.005-ratio)/0.001))
    entropyRatioScore := 1 / (1 + math.Exp(-(0.0195-entropyRatio)/0.001))

    entropyScore := 1 / (1 + math.Exp((entropy-7.1)/0.5))

    score := varianceWeight*varianceScore +
             ratioWeight*ratioScore +
             entropyRatioWeight*entropyRatioScore +
             entropyWeight*entropyScore

    isEncrypted := score >= 0.7

    return isEncrypted, variance, ratio, entropy, entropyRatio, binaryRatio, score
}
func calculateVariance(data []float64) float64 {
    var sum, mean, variance float64
    n := float64(len(data))

    for _, value := range data {
        sum += value
    }
    mean = sum / n

    for _, value := range data {
        variance += (value - mean) * (value - mean)
    }
    return variance / n
}

func calculateBinaryRatio(data []byte) float64 {
    ones := 0
    total := len(data) * 8

    for _, b := range data {
        for i := 0; i < 8; i++ {
            if (b & (1 << uint(i))) != 0 {
                ones++
            }
        }
    }

    zeros := total - ones
    if zeros == 0 {
        return float64(total)
    }
    return float64(ones) / float64(zeros)
}