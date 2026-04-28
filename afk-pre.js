const mineflayer = require('mineflayer')

let startShards = null
let currentShards = 0
let gainedShards = 0
let shardTimer = "unknown"

function logInfo() {
  console.log(
    `Timer: ${shardTimer} | Shards: ${currentShards} | AFK gained: ${gainedShards}`
  )
}

function startBot() {

  const bot = mineflayer.createBot({
    host: "donutsmp.net",
    port: 25565,
    username: "tempmail2k9@gmail.com",
    auth: "microsoft",
    version: "1.21.11"
  })

  bot.on('spawn', () => {
    console.log("Bot đã vào server")

    // nhảy chống AFK
    setInterval(() => {
      bot.setControlState('jump', true)
      setTimeout(() => bot.setControlState('jump', false), 400)
    }, 2000)
  })

  // đọc actionbar
  bot.on('actionBar', (msg) => {
    const text = msg.toString()

    if (text.includes("Next shard")) {
      shardTimer = text
      logInfo()
    }
  })

  // đọc scoreboard
  bot.on('scoreUpdated', (item) => {

    const line = item.name?.toString()
    if (!line) return

    if (line.includes("Shards")) {

      const match = line.match(/\d+/)
      if (!match) return

      currentShards = parseInt(match[0])

      if (startShards === null) {
        startShards = currentShards
      }

      gainedShards = currentShards - startShards

      logInfo()
    }
  })

  // reconnect
  bot.on('end', () => {
    console.log("Disconnected → reconnect 5s")
    setTimeout(startBot, 5000)
  })

  bot.on('error', console.log)
}

startBot()