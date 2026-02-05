import std/[times, monotimes, strformat, strutils, osproc]
import leansig, multisig

proc getSystemInfo(): string =
  var info = ""
  let uname = execProcess("uname -sr").strip()
  let cpu = execProcess("lscpu | grep 'Model name' | cut -d: -f2").strip()
  let cores = execProcess("nproc").strip()
  let mem = execProcess("free -h | grep Mem | awk '{print $2}'").strip()
  info.add("System: " & uname & "\n")
  info.add("CPU: " & cpu & " (" & cores & " cores)\n")
  info.add("Memory: " & mem & "\n")
  info.add("Nim: " & NimVersion & "\n")
  result = info

proc bench(name: string, iters: int, fn: proc()) =
  var times: seq[float] = @[]
  for i in 0..<3: fn()
  for i in 0..<iters:
    let s = getMonoTime()
    fn()
    times.add((getMonoTime() - s).inNanoseconds.float)
  var t, mn, mx = 0.0
  for i, v in times:
    t += v
    if i == 0: mn = v; mx = v
    if v < mn: mn = v
    if v > mx: mx = v
  let avgMs = t / iters.float / 1_000_000
  let avgNs = t / iters.float
  # Get CPU frequency for cycle calculation
  let cpuMhz = try:
    execProcess("lscpu | grep 'CPU max MHz' | awk '{print $NF}'").strip().parseFloat()
  except:
    try:
      execProcess("lscpu | grep 'CPU MHz' | head -1 | awk '{print $NF}'").strip().parseFloat()
    except:
      1700.0  # fallback to default
  let cycles = (avgNs * cpuMhz) / 1000.0
  echo "\n", "=".repeat(50), "\n", name, "\n", "=".repeat(50)
  echo fmt"Avg: {avgMs:.2f} ms"
  echo fmt"Min: {mn / 1_000_000:.2f} ms | Max: {mx / 1_000_000:.2f} ms"
  echo fmt"CPU Cycles/Op: {cycles:.0f} cycles ({cpuMhz:.0f} MHz)"

when isMainModule:
  echo "\n╔", "═".repeat(58), "╗"
  echo "║", " ".repeat(15), "nim-leansig Benchmarks", " ".repeat(21), "║"
  echo "╚", "═".repeat(58), "╝"
  echo ""
  echo getSystemInfo()
  echo "=".repeat(60)
  
  bench("Keypair Gen (100 epochs)", 10, proc() =
    var k = newLeanSigKeyPair("s", 0, 100)
    k.free()
  )
  
  var kp = newLeanSigKeyPair("x", 0, 100)
  var msg = newSeq[byte](messageLength().int)
  for i in 0..<msg.len: msg[i] = byte(i mod 256)
  
  bench("Signing", 30, proc() =
    var s = kp.sign(msg, 0)
    s.free()
  )
  
  var sig = kp.sign(msg, 0)
  bench("Verification", 30, proc() =
    discard sig.verify(msg, kp, 0)
  )
  sig.free()
  kp.free()
  
  setupProver()
  setupVerifier()
  
  bench("XMSS Keypair (log=3)", 5, proc() =
    var k = newXmssKeyPair("y", 0, 3)
    k.free()
  )
  
  var xkp = newXmssKeyPair("z", 0, 4)
  var xmsg = newSeq[byte](xmssMsgLen())
  for i in 0..<xmsg.len: xmsg[i] = byte(i mod 256)
  
  bench("XMSS Signing", 20, proc() =
    var s = xkp.sign(xmsg, 0)
    s.free()
  )
  
  var xsig = xkp.sign(xmsg, 0)
  bench("XMSS Verification", 20, proc() =
    discard xsig.verify(xmsg, xkp, 0)
  )
  xsig.free()
  xkp.free()
  
  var k1 = newXmssKeyPair("a", 0, 3)
  var k2 = newXmssKeyPair("b", 0, 3)
  var s1 = k1.sign(xmsg, 0)
  var s2 = k2.sign(xmsg, 0)
  
  bench("Aggregate 2 Sigs", 5, proc() =
    var p = aggregate([k1, k2], [s1, s2], xmsg, 0)
    p.free()
  )
  
  var pr = aggregate([k1, k2], [s1, s2], xmsg, 0)
  bench("Verify Aggregated (2)", 5, proc() =
    discard pr.verifyAggregated([k1, k2], xmsg, 0)
  )
