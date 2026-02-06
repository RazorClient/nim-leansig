import std/[times, monotimes, strformat, strutils, osproc]
import leansig, multisig

const
  warmupRuns = 3
  nanosecondsPerMillisecond = 1_000_000.0
  kilohertzPerMegahertz = 1000.0
  defaultCpuMhz = 1700.0
  sectionWidth = 50
  titleBorderWidth = 58
  pageDividerWidth = 60

  leanSigEpochWindow = 100'u
  leanSigKeygenIters = 10
  leanSigSignIters = 30
  leanSigVerifyIters = 30

  xmssFastLogLifetime = 3'u
  xmssLongerLogLifetime = 4'u
  xmssKeygenIters = 5
  xmssSignIters = 20
  xmssVerifyIters = 20
  aggregateIters = 5
  aggregateVerifyIters = 5

proc makeSequentialMessage(length: int): seq[byte] =
  result = newSeq[byte](length)
  for index in 0 ..< length:
    result[index] = byte(index mod 256)

proc parseCpuMhz(command: string): float =
  execProcess(command).strip().parseFloat()

proc detectCpuMhz(): float =
  for command in [
    "lscpu | grep 'CPU max MHz' | awk '{print $NF}'",
    "lscpu | grep 'CPU MHz' | head -1 | awk '{print $NF}'",
  ]:
    try:
      return parseCpuMhz(command)
    except CatchableError:
      discard
  defaultCpuMhz

proc getSystemInfo(): string =
  var systemInfo = ""
  let uname = execProcess("uname -sr").strip()
  let cpu = execProcess("lscpu | grep 'Model name' | cut -d: -f2").strip()
  let cores = execProcess("nproc").strip()
  let mem = execProcess("free -h | grep Mem | awk '{print $2}'").strip()
  systemInfo.add("System: " & uname & "\n")
  systemInfo.add("CPU: " & cpu & " (" & cores & " cores)\n")
  systemInfo.add("Memory: " & mem & "\n")
  systemInfo.add("Nim: " & NimVersion & "\n")
  result = systemInfo

proc runBenchmark(name: string, iterations: int, benchmarkFn: proc()) =
  var sampleDurationsNs: seq[float] = @[]

  for _ in 0 ..< warmupRuns:
    benchmarkFn()

  for _ in 0 ..< iterations:
    let startTime = getMonoTime()
    benchmarkFn()
    sampleDurationsNs.add((getMonoTime() - startTime).inNanoseconds.float)

  var totalNanoseconds = 0.0
  var minNanoseconds = sampleDurationsNs[0]
  var maxNanoseconds = sampleDurationsNs[0]
  for duration in sampleDurationsNs:
    totalNanoseconds += duration
    if duration < minNanoseconds:
      minNanoseconds = duration
    if duration > maxNanoseconds:
      maxNanoseconds = duration

  let averageNanoseconds = totalNanoseconds / iterations.float
  let averageMilliseconds = averageNanoseconds / nanosecondsPerMillisecond
  let cpuMhz = detectCpuMhz()
  let estimatedCycles = (averageNanoseconds * cpuMhz) / kilohertzPerMegahertz

  echo "\n", "=".repeat(sectionWidth), "\n", name, "\n", "=".repeat(sectionWidth)
  echo fmt"Avg: {averageMilliseconds:.2f} ms"
  echo fmt"Min: {minNanoseconds / nanosecondsPerMillisecond:.2f} ms | Max: {maxNanoseconds / nanosecondsPerMillisecond:.2f} ms"
  echo fmt"CPU Cycles/Op: {estimatedCycles:.0f} cycles ({cpuMhz:.0f} MHz)"

proc runAllBenchmarks() =
  echo "\n╔", "═".repeat(titleBorderWidth), "╗"
  echo "║", " ".repeat(15), "nim-leansig Benchmarks", " ".repeat(21), "║"
  echo "╚", "═".repeat(titleBorderWidth), "╝"
  echo ""
  echo getSystemInfo()
  echo "=".repeat(pageDividerWidth)

  runBenchmark(
    "Keypair Gen (100 epochs)",
    leanSigKeygenIters,
    proc() =
      var transientKeyPair = newLeanSigKeyPair("s", 0, leanSigEpochWindow)
      transientKeyPair.free(),
  )

  var leanSigKeyPair = newLeanSigKeyPair("x", 0, leanSigEpochWindow)
  defer:
    leanSigKeyPair.free()
  let leanSigMessage = makeSequentialMessage(messageLength().int)

  runBenchmark(
    "Signing",
    leanSigSignIters,
    proc() =
      var transientSignature = leanSigKeyPair.sign(leanSigMessage, 0)
      transientSignature.free(),
  )

  var leanSigSignature = leanSigKeyPair.sign(leanSigMessage, 0)
  defer:
    leanSigSignature.free()
  runBenchmark(
    "Verification",
    leanSigVerifyIters,
    proc() =
      discard leanSigSignature.verify(leanSigMessage, leanSigKeyPair, 0),
  )

  setupProver()
  setupVerifier()

  runBenchmark(
    "XMSS Keypair (log=3)",
    xmssKeygenIters,
    proc() =
      var transientXmssKeyPair = newXmssKeyPair("y", 0, xmssFastLogLifetime)
      transientXmssKeyPair.free(),
  )

  var xmssKeyPair = newXmssKeyPair("z", 0, xmssLongerLogLifetime)
  defer:
    xmssKeyPair.free()
  let xmssMessage = makeSequentialMessage(xmssMsgLen())

  runBenchmark(
    "XMSS Signing",
    xmssSignIters,
    proc() =
      var transientXmssSignature = xmssKeyPair.sign(xmssMessage, 0)
      transientXmssSignature.free(),
  )

  var xmssSignature = xmssKeyPair.sign(xmssMessage, 0)
  defer:
    xmssSignature.free()
  runBenchmark(
    "XMSS Verification",
    xmssVerifyIters,
    proc() =
      discard xmssSignature.verify(xmssMessage, xmssKeyPair, 0),
  )

  var firstSignerKeyPair = newXmssKeyPair("a", 0, xmssFastLogLifetime)
  defer:
    firstSignerKeyPair.free()
  var secondSignerKeyPair = newXmssKeyPair("b", 0, xmssFastLogLifetime)
  defer:
    secondSignerKeyPair.free()
  var firstSignerSignature = firstSignerKeyPair.sign(xmssMessage, 0)
  defer:
    firstSignerSignature.free()
  var secondSignerSignature = secondSignerKeyPair.sign(xmssMessage, 0)
  defer:
    secondSignerSignature.free()

  runBenchmark(
    "Aggregate 2 Sigs",
    aggregateIters,
    proc() =
      var transientProof = aggregate(
        [firstSignerKeyPair, secondSignerKeyPair],
        [firstSignerSignature, secondSignerSignature],
        xmssMessage,
        0,
      )
      transientProof.free(),
  )

  var aggregateProof = aggregate(
    [firstSignerKeyPair, secondSignerKeyPair],
    [firstSignerSignature, secondSignerSignature],
    xmssMessage,
    0,
  )
  defer:
    aggregateProof.free()
  runBenchmark(
    "Verify Aggregated (2)",
    aggregateVerifyIters,
    proc() =
      discard aggregateProof.verifyAggregated(
        [firstSignerKeyPair, secondSignerKeyPair], xmssMessage, 0
      ),
  )

when isMainModule:
  runAllBenchmarks()
