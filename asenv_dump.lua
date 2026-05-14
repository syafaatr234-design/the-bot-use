local warn = warn or function() end

local _origPcall = pcall
local _origXpcall = xpcall
local _origError = error

local debugLibrary = debug
_G._VERSION = "Luau"
local setHook = debug.sethook
local getInfo = debug.getinfo
local getTraceback = debug.traceback
local loadFunction = load
local loadStringFunction = loadstring or load
local pcallFunction = pcall
local xpcallFunction = xpcall
local errorFunction = error
local typeFunction = type
local getMetatableFunction = getmetatable
local rawEqualFunction = rawequal
local toStringFunction = tostring
local toNumberFunction = tonumber
local ioLibrary = io
local osLibrary = os
local pairsFunction = pairs
local ipairsFunction = ipairs
local tableUnpackFunction = table.unpack or unpack
local proxyTable = {}
proxyTable.__index = proxyTable
local configuration = {
    MAX_DEPTH = 15,
    MAX_TABLE_ITEMS = 150,
    OUTPUT_FILE = "dumped_output.lua",
    VERBOSE = false,
    TRACE_CALLBACKS = true,
    TIMEOUT_SECONDS = 6.57,
    MAX_REPEATED_LINES = 8,
    MIN_DEOBF_LENGTH = 150,
    MAX_OUTPUT_SIZE = 6 * 1024 * 1024,
    CONSTANT_COLLECTION = true,
    INSTRUMENT_LOGIC = true
}
local inputKey = (arg and arg[3]) or "NoKey"
if arg and arg[3] then
    print("[Dumper] Auto-Input Key Detected: " .. toStringFunction(inputKey))
end
local dumperState = {
    output = {},
    indent = 0,
    registry = {},
    reverse_registry = {},
    names_used = {},
    parent_map = {},
    property_store = {},
    call_graph = {},
    variable_types = {},
    string_refs = {},
    proxy_id = 0,
    callback_depth = 0,
    pending_iterator = false,
    last_http_url = nil,
    last_emitted_line = nil,
    repetition_count = 0,
    current_size = 0,
    ls_counter = 0
}
local _at = {
    mem          = {},
    tags         = {},
    sigs         = {},
    acts         = {},
    json         = {},
    enum         = {},
    svcCache     = {},
    typeOverride = {},
    connState    = {},
    debugIds     = {},
    debugIdCtr   = 0,
    instTags     = {},
    attrs        = {},
    children     = {},
    threadLike   = {},
    vectors      = {},
    buffers      = {},
    userdata     = {},
    localPlayer  = nil,
    weldRegistry = {},
    services     = {},
    folders      = {},
    files        = {},
    refBase      = {},
    metaHooks    = {},
    currentNamecallMethod = nil,
    inMetaHook   = false,
    pendingHeartbeat = {},
    locEntries = {},
    signalCallbacks = {},  -- AT5: live signal firing
    animateScript = nil,   -- AT3: getrunningscripts
}
setmetatable(_at.debugIds, {__mode = "k"})
setmetatable(_at.instTags, {__mode = "k"})
setmetatable(_at.attrs, {__mode = "k"})
setmetatable(_at.children, {__mode = "k"})
setmetatable(_at.threadLike, {__mode = "k"})
setmetatable(_at.vectors, {__mode = "k"})
setmetatable(_at.buffers, {__mode = "k"})
setmetatable(_at.userdata, {__mode = "k"})
setmetatable(_at.refBase, {__mode = "k"})
local function _getDebugId(p)
    if not _at.debugIds[p] then
        _at.debugIdCtr = _at.debugIdCtr + 1
        local n = _at.debugIdCtr
        _at.debugIds[p] = toStringFunction(n * 17 + 3) .. "-" .. toStringFunction(n * 97 + 11)
    end
    return _at.debugIds[p]
end
local function _removeChild(parent, child)
    local list = parent and _at.children[parent]
    if not list then return end
    for i = #list, 1, -1 do
        if list[i] == child then table.remove(list, i) end
    end
end
local function _setParent(child, parent)
    local oldParent = dumperState.parent_map[child]
    if oldParent == parent then return end
    _removeChild(oldParent, child)
    dumperState.parent_map[child] = parent
    if parent then
        _at.children[parent] = _at.children[parent] or {}
        table.insert(_at.children[parent], child)
        -- skip signal firing for internal proxy types
        local childType = _at.typeOverride[child]
        local parentType = _at.typeOverride[parent]
        if childType == "RBXScriptSignal" or childType == "RBXScriptConnection"
        or parentType == "RBXScriptSignal" or parentType == "RBXScriptConnection" then
            return
        end
        -- fire ChildAdded on direct parent only
        if _at.signalCallbacks[parent] then
            for _, cb in ipairsFunction(_at.signalCallbacks[parent].ChildAdded or {}) do
                pcallFunction(cb, child)
            end
        end
        -- fire DescendantAdded on direct parent and its ancestors
        local ancestor = parent
        while ancestor do
            if _at.signalCallbacks[ancestor] then
                for _, cb in ipairsFunction(_at.signalCallbacks[ancestor].DescendantAdded or {}) do
                    pcallFunction(cb, child)
                end
            end
            ancestor = dumperState.parent_map[ancestor]
        end
    end
end
local function _isDescendantOf(child, parent)
    local cur = dumperState.parent_map[child]
    while cur do
        if cur == parent then return true end
        cur = dumperState.parent_map[cur]
    end
    return false
end
local function _getAllDescendants(root, out)
    out = out or {}
    for _, child in ipairsFunction(_at.children[root] or {}) do
        table.insert(out, child)
        _getAllDescendants(child, out)
    end
    return out
end
local numericArg = (arg and toNumberFunction(arg[4])) or (arg and toNumberFunction(arg[3])) or 123456789
local proxyMarker = {}
local function isProxyTable(target)
    if typeFunction(target) ~= "table" then
        return false
    end
    local success, result = pcallFunction( function() return rawget(target, proxyMarker) == true end )
    return success and result
end
local function getProxyValue(target)
    if isProxyTable(target) then
        return rawget(target, "__value") or 0
    end
    return 0
end
local loadStringFunction = loadstring or load
local printFunction = print
local warnFunction = warn or function() end
local pairsFunction = pairs
local ipairsFunction = ipairs
local typeFunction = type
local toStringFunction = tostring
local proxyList = {}
local function isProxy(target)
    if typeFunction(target) ~= "table" then
        return false
    end
    local success, result = pcallFunction( function() return rawget(target, proxyList) == true end )
    return success and result
end
local function getProxyId(target)
    if not isProxy(target) then
        return nil
    end
    return rawget(target, "__proxy_id")
end
local function processString(inputString)
    if typeFunction(inputString) ~= "string" then
        return '"'
    end
    local outputParts = {}
    local currentIndex, totalLength = 1, #inputString
    local function cleanEscapes(content)
        return content:gsub( "(.)", function(escapedChar)
            if escapedChar:match('[abfnrtv%\'%"%[%]0-9xu]') then
                return "" .. escapedChar
            end
            return escapedChar
        end )
    end
    local function stripLuauSyntax(rawCode)
        if not rawCode or rawCode == "" then
            return rawCode
        end
        rawCode = rawCode:gsub("\239\187\191", "")
        rawCode = rawCode:gsub("r\n", "\n"):gsub("r", "\n")
        rawCode = rawCode:gsub("\226\128\168", "\n"):gsub("\226\128\169", "\n")
        rawCode = rawCode:gsub("%-%-!%a+[^\n]*", "")
        rawCode = rawCode:gsub("([^\n]*)", function(line)
            if line:match("^%s*export%s+type%s+") or line:match("^%s*type%s+[%a_][%w_]*%s*=") then
                return "-- " .. line
            end
            return line
        end)
        rawCode = rawCode:gsub("local%s+([%a_][%w_]*)%s*<[%a_][%w_]*>%s*=", "local %1 =")
        rawCode = rawCode:gsub("(function%s+[%a_][%w_%.:]*)%s*<[^>\n%(]+>%s*%(", "%1(")
        rawCode = rawCode:gsub("([%(%s,])%.%.%.%s*:%s*[%a_][%w_%.]*%??", "%1...")
        rawCode = rawCode:gsub("([%(%s,])([%a_][%w_]*)%s*:%s*[%a_][%w_%.]*%s*%b<>%??", "%1%2")
        rawCode = rawCode:gsub("([%(%s,])([%a_][%w_]*)%s*:%s*[%a_][%w_%.]*%??(%s*[%),=])", "%1%2%3")
        rawCode = rawCode:gsub("%)%s*:%s*[%a_][%w_%.]*%s*%b<>%??", ")")
        rawCode = rawCode:gsub("%)%s*:%s*[%a_][%w_%.]*%??(%s*[%),=])", ")%1")
        rawCode = rawCode:gsub("%s*::%s*[%a_][%w_%.]*%s*%b<>%??", "")
        rawCode = rawCode:gsub("%s*::%s*[%a_][%w_%.]*%??", "")
        return rawCode
    end
    local function parseExpression(rawCode)
        if not rawCode or rawCode == '"' then
            return ""
        end
        rawCode = stripLuauSyntax(rawCode)
        rawCode = rawCode:gsub( "0[bB]([01_]+)", function(binaryString)
            local cleanBinary = binaryString:gsub("_", "")
            local decimalValue = toNumberFunction(cleanBinary, 2)
            return decimalValue and toStringFunction(decimalValue) or "0"
        end )
        rawCode = rawCode:gsub( "0[xX]([%x_]+)", function(hexString)
            local cleanHex = hexString:gsub("_", "")
            return "0x" .. cleanHex
        end )
        while rawCode:match("%d_+%d") do
            rawCode = rawCode:gsub("(%d)_+(%d)", "%1%2")
        end
        local operators = {{"+=", "+"}, {"-=", "-"}, {"*=", "*"}, {"/=", "/"}, {"%%=", "%%"}, {"%^=", "^"}, {"%.%.=", ".."}}
        for _, opPair in ipairsFunction(operators) do
            local operatorAssignment, operator = opPair[1], opPair[2]
            rawCode = rawCode:gsub( "([%a_][%w_]*%b[])%s*" .. operatorAssignment, function(varName)
                return varName .. " = " .. varName .. " " .. operator .. " "
            end )
            rawCode = rawCode:gsub( "([%a_][%w_]*[%.%a_%d][%w_%.]*%.[%a_][%w_]*)%s*" .. operatorAssignment, function(varName)
                return varName .. " = " .. varName .. " " .. operator .. " "
            end )
            rawCode = rawCode:gsub( "([^%w_%.%]%):])([%a_][%w_]*)%s*" .. operatorAssignment, function(prefix, varName)
                return prefix .. varName .. " = " .. varName .. " " .. operator .. " "
            end )
            rawCode = rawCode:gsub( "^([%a_][%w_]*)%s*" .. operatorAssignment, function(varName)
                return varName .. " = " .. varName .. " " .. operator .. " "
            end )
        end

        rawCode = rawCode:gsub("([%a_][%w_]*%b[])%s*%+%+",            "%1 = %1 + 1")
        rawCode = rawCode:gsub("([%a_][%w_]*%.[%w_%.]*[%w_])%s*%+%+","%1 = %1 + 1")
        rawCode = rawCode:gsub("([%a_][%w_]*)%s*%+%+",                "%1 = %1 + 1")
        rawCode = rawCode:gsub("%+%+%s*([%a_][%w_]*%b[])",            "%1 = %1 + 1")
        rawCode = rawCode:gsub("%+%+%s*([%a_][%w_]*%.[%w_%.]*[%w_])","%1 = %1 + 1")
        rawCode = rawCode:gsub("%+%+%s*([%a_][%w_]*)",                "%1 = %1 + 1")
        rawCode = rawCode:gsub("%+%+", "+")

        rawCode = rawCode:gsub("([^%w_])continue([^%w_])", "%1__LC__()%2")
        rawCode = rawCode:gsub("^continue([^%w_])", "__LC__()%1")
        rawCode = rawCode:gsub("([^%w_])continue$", "%1__LC__()")
        return rawCode
    end
    local function getBracketCount(index)
        local count = 0
        while index <= totalLength and inputString:byte(index) == 61 do
            count = count + 1
            index = index + 1
        end
        return count, index
    end
    local function findClosingBracket(startIndex, bracketCount)
        local closingPattern = "]" .. string.rep("=", bracketCount) .. "]"
        local start, finish = inputString:find(closingPattern, startIndex, true)
        return finish or totalLength
    end
    local segmentStart = 1
    while currentIndex <= totalLength do
        local byteValue = inputString:byte(currentIndex)
        if byteValue == 91 then
            local bracketCount, nextIndex = getBracketCount(currentIndex + 1)
            if nextIndex <= totalLength and inputString:byte(nextIndex) == 91 then
                table.insert(outputParts, parseExpression(inputString:sub(segmentStart, currentIndex - 1)))
                local startSegment = currentIndex
                local endSegment = findClosingBracket(nextIndex + 1, bracketCount)
                table.insert(outputParts, inputString:sub(startSegment, endSegment))
                currentIndex = endSegment
                segmentStart = currentIndex + 1
            end
        elseif byteValue == 45 and currentIndex + 1 <= totalLength and inputString:byte(currentIndex + 1) == 45 then
            table.insert(outputParts, parseExpression(inputString:sub(segmentStart, currentIndex - 1)))
            local startSegment = currentIndex
            if currentIndex + 2 <= totalLength and inputString:byte(currentIndex + 2) == 91 then
                local bracketCount, nextIndex = getBracketCount(currentIndex + 3)
                if nextIndex <= totalLength and inputString:byte(nextIndex) == 91 then
                    local endSegment = findClosingBracket(nextIndex + 1, bracketCount)
                    table.insert(outputParts, inputString:sub(startSegment, endSegment))
                    currentIndex = endSegment
                    segmentStart = currentIndex + 1
                    currentIndex = currentIndex + 1
                end
            end
            local lineBreak = inputString:find("\n", currentIndex + 2, true)
            if lineBreak then
                currentIndex = lineBreak
            else
                currentIndex = totalLength
            end
            table.insert(outputParts, inputString:sub(startSegment, currentIndex))
            segmentStart = currentIndex + 1
        elseif byteValue == 34 or byteValue == 39 or byteValue == 96 then
            table.insert(outputParts, parseExpression(inputString:sub(segmentStart, currentIndex - 1)))
            local quoteType = byteValue
            local startSegment = currentIndex
            currentIndex = currentIndex + 1
            while currentIndex <= totalLength do
                local charByte = inputString:byte(currentIndex)
                if charByte == 92 then
                    currentIndex = currentIndex + 1
                elseif charByte == quoteType then
                    break
                end
                currentIndex = currentIndex + 1
            end
            local extractedContent = inputString:sub(startSegment + 1, currentIndex - 1)
            extractedContent = cleanEscapes(extractedContent)
            if quoteType == 96 then
                table.insert(outputParts, '"' .. extractedContent:gsub('"', '"') .. '"')
            else
                local quoteChar = string.char(quoteType)
                table.insert(outputParts, quoteChar .. extractedContent .. quoteChar)
            end
            segmentStart = currentIndex + 1
        end
        currentIndex = currentIndex + 1
    end
    table.insert(outputParts, parseExpression(inputString:sub(segmentStart)))
    return table.concat(outputParts)
end
local function safeLoad(code, chunkName)
    local loadedFunc, errorMessage = loadStringFunction(code, chunkName)
    if loadedFunc then
        return loadedFunc
    end
    printFunction("\n[CRITICAL ERROR] Failed to load script!")
    printFunction("[LUA_LOAD_FAIL] " .. toStringFunction(errorMessage))
    local errorLine = toNumberFunction(errorMessage:match(":(%d+):"))
    local errorNear = errorMessage:match("near '([^']+)'")
    if errorNear then
        local foundIndex = code:find(errorNear, 1, true)
        if foundIndex then
            local startCtx = math.max(1, foundIndex - 50)
            local endCtx = math.min(#code, foundIndex + 50)
            printFunction("Context around error:")
            printFunction("..." .. code:sub(startCtx, endCtx) .. "...")
        end
    end
    local debugFile = ioLibrary.open("DEBUG_FAILED_TRANSPILE.lua", "w")
    if debugFile then
        debugFile:write(code)
        debugFile:close()
        printFunction("[*] Saved to 'DEBUG_FAILED_TRANSPILE.lua' for inspection")
    end
    return nil, errorMessage
end
local function emitOutput(data, isInline)
    if dumperState.limit_reached then
        return
    end
    if data == nil then
        return
    end
    local indentPrefix = isInline and "" or string.rep("    ", dumperState.indent)
    local lineString = indentPrefix .. toStringFunction(data)
    local lineSize = #lineString + 1
    if dumperState.current_size + lineSize > configuration.MAX_OUTPUT_SIZE then
        dumperState.limit_reached = true
        local warningMessage = "-- [CRITICAL] Dump stopped: File size exceeded 6MB limit."
        table.insert(dumperState.output, warningMessage)
        dumperState.current_size = dumperState.current_size + #warningMessage
        errorFunction("DUMP_LIMIT_EXCEEDED")
    end
    if lineString == dumperState.last_emitted_line then
        dumperState.repetition_count = dumperState.repetition_count + 1
        if dumperState.repetition_count <= configuration.MAX_REPEATED_LINES then
            table.insert(dumperState.output, lineString)
            dumperState.current_size = dumperState.current_size + lineSize
        elseif dumperState.repetition_count == configuration.MAX_REPEATED_LINES + 1 then
            local suppressMessage = indentPrefix .. "-- [Repeated lines suppressed...]"
            table.insert(dumperState.output, suppressMessage)
            dumperState.current_size = dumperState.current_size + #suppressMessage
        end
    else
        dumperState.last_emitted_line = lineString
        dumperState.repetition_count = 0
        table.insert(dumperState.output, lineString)
        dumperState.current_size = dumperState.current_size + lineSize
    end
    if configuration.VERBOSE and dumperState.repetition_count <= 1 then
        printFunction(lineString)
    end
end
local function emitComment(data)
    emitOutput("-- " .. toStringFunction(data or ""))
end
local function addEmptyLine()
    dumperState.last_emitted_line = nil
    table.insert(dumperState.output, "")
end
local function getFullOutput()
    return table.concat(dumperState.output, "\n")
end
local function saveToFile(filePath)
    local fileHandle = ioLibrary.open(filePath or configuration.OUTPUT_FILE, "w")
    if fileHandle then
        fileHandle:write(getFullOutput())
        fileHandle:close()
        return true
    end
    return false
end
local function formatValue(value)
    if value == nil then
        return "nil"
    end
    if typeFunction(value) == "string" then
        return value
    end
    if typeFunction(value) == "number" or typeFunction(value) == "boolean" then
        return toStringFunction(value)
    end
    if typeFunction(value) == "table" then
        if dumperState.registry[value] then
            return dumperState.registry[value]
        end
        if isProxy(value) then
            local proxyId = getProxyId(value)
            return proxyId and "proxy_" .. proxyId or "proxy"
        end
    end
    local success, result = pcallFunction(toStringFunction, value)
    return success and result or "unknown"
end
local function formatStringLiteral(value)
    local rawValue = formatValue(value)
    local escapedValue = rawValue:gsub("", ""):gsub('"', '"'):gsub("\n", "\n"):gsub("\r", "\r"):gsub("\t", "\t")
    return '"' .. escapedValue .. '"'
end
local serviceNames = {
    Players = "Players",
    Workspace = "Workspace",
    ReplicatedStorage = "ReplicatedStorage",
    ServerStorage = "ServerStorage",
    ServerScriptService = "ServerScriptService",
    StarterGui = "StarterGui",
    StarterPack = "StarterPack",
    StarterPlayer = "StarterPlayer",
    Lighting = "Lighting",
    SoundService = "SoundService",
    Chat = "Chat",
    RunService = "RunService",
    UserInputService = "UserInputService",
    TweenService = "TweenService",
    GroupService = "GroupService",
    AnimationClipProvider = "AnimationClipProvider",
    HttpService = "HttpService",
    MarketplaceService = "MarketplaceService",
    TeleportService = "TeleportService",
    PathfindingService = "PathfindingService",
    CollectionService = "CollectionService",
    PhysicsService = "PhysicsService",
    ProximityPromptService = "ProximityPromptService",
    ContextActionService = "ContextActionService",
    GuiService = "GuiService",
    HapticService = "HapticService",
    VRService = "VRService",
    CoreGui = "CoreGui",
    Teams = "Teams",
    InsertService = "InsertService",
    DataStoreService = "DataStoreService",
    MessagingService = "MessagingService",
    TextService = "TextService",
    TextChatService = "TextChatService",
    NetworkClient = "NetworkClient",
    ContentProvider = "ContentProvider",
    Debris = "Debris",
    MemStorageService = "MemStorageService",
    ChangeHistoryService = "ChangeHistoryService",
    PlayerEmulatorService = "PlayerEmulatorService",
    StylingService = "StylingService",
    ScriptContext = "ScriptContext",
    LocalizationService = "LocalizationService",
    PolicyService = "PolicyService",
    CaptureService = "CaptureService",
    AnalyticsService = "AnalyticsService",
    EncodingService = "EncodingService",
    CorePackages = "CorePackages",
    RobloxReplicatedStorage = "RobloxReplicatedStorage",
    RobloxGui = "RobloxGui",
    AvatarEditorService = "AvatarEditorService",
    SocialService = "SocialService",
    VoiceChatService = "VoiceChatService",
    AdService = "AdService",
    GeometryService = "GeometryService",
    AssetService = "AssetService",
    LocalizationService = "LocalizationService",
    NotificationService = "NotificationService",
    ProcessInstancePhysicsService = "ProcessInstancePhysicsService",
    FriendService = "FriendService",
    SessionService = "SessionService",
    TimerService = "TimerService",
    TouchInputService = "TouchInputService",
    GamepadService = "GamepadService",
    KeyboardService = "KeyboardService",
    MouseService = "MouseService",
    OmniRecommendationsService = "OmniRecommendationsService",
    PerformanceService = "PerformanceService",
    PlatformFriendService = "PlatformFriendService",
    ReplicatedFirst = "ReplicatedFirst",
    SpawnLocation = "SpawnLocation",
    LogService = "LogService",
    Stats = "Stats",
    TweenService = "TweenService",
    Debris = "Debris",
    CoreGui = "CoreGui",
    MarketplaceService = "MarketplaceService",
    NotificationService = "NotificationService",
    GuidRegistryService = "GuidRegistryService",
    NetworkServer = "NetworkServer",
    Geometry = "Geometry",
    VirtualInputManager = "VirtualInputManager",
    MLModelDeliveryService = "MLModelDeliveryService",
    PartyEmulatorService = "PartyEmulatorService",
    PlatformFriendsService = "PlatformFriendsService",
    FriendService = "FriendService",
    OmniRecommendationsService = "OmniRecommendationsService",
    PerformanceControlService = "PerformanceControlService",
    RbxAnalyticsService = "RbxAnalyticsService",
    AbuseReportService = "AbuseReportService",
    AdService = "AdService",
    AdPortalService = "AdPortalService",
    AppUpdateService = "AppUpdateService",
    BrowserService = "BrowserService",
    CookiesService = "CookiesService",
    CoreGui = "CoreGui",
    GamesService = "GamesService",
    KeyboardService = "KeyboardService",
    MarketplaceService = "MarketplaceService",
    MouseService = "MouseService",
    NotificationService = "NotificationService",
    PurchaseDataService = "PurchaseDataService",
    TimerService = "TimerService",
    UGCValidationService = "UGCValidationService",
}
local serviceShortcuts = {
    Players = "Players",
    UserInputService = "UIS",
    RunService = "RunService",
    ReplicatedStorage = "ReplicatedStorage",
    TweenService = "TweenService",
    Workspace = "Workspace",
    Lighting = "Lighting",
    StarterGui = "StarterGui",
    CoreGui = "CoreGui",
    HttpService = "HttpService",
    MarketplaceService = "MarketplaceService",
    DataStoreService = "DataStoreService",
    TeleportService = "TeleportService",
    SoundService = "SoundService",
    Chat = "Chat",
    Teams = "Teams",
    ProximityPromptService = "ProximityPromptService",
    ContextActionService = "ContextActionService",
    CollectionService = "CollectionService",
    PathfindingService = "PathfindingService",
    Debris = "Debris"
}
local classParents = {
    DataModel = {"DataModel", "ServiceProvider", "Instance"},
    Workspace = {"Workspace", "WorldRoot", "Model", "PVInstance", "Instance"},
    Camera = {"Camera", "Instance"},
    Players = {"Players", "Instance"},
    Player = {"Player", "Instance"},
    PlayerGui = {"PlayerGui", "BasePlayerGui", "Instance"},
    Backpack = {"Backpack", "Instance"},
    PlayerScripts = {"PlayerScripts", "Instance"},
    Folder = {"Folder", "Instance"},
    Model = {"Model", "PVInstance", "Instance"},
    Part = {"Part", "BasePart", "PVInstance", "Instance"},
    BasePart = {"BasePart", "PVInstance", "Instance"},
    ModuleScript = {"ModuleScript", "LuaSourceContainer", "Instance"},
    LocalScript = {"LocalScript", "Script", "LuaSourceContainer", "Instance"},
    Script = {"Script", "LuaSourceContainer", "Instance"},
    Humanoid = {"Humanoid", "Instance"},
    SoundService = {"SoundService", "Instance"},
    Lighting = {"Lighting", "Instance"},
    HttpService = {"HttpService", "Instance"},
    TweenService = {"TweenService", "Instance"},
    RunService = {"RunService", "Instance"},
    TextService = {"TextService", "Instance"},
    GuiService = {"GuiService", "Instance"},
    ContentProvider = {"ContentProvider", "Instance"},
    CollectionService = {"CollectionService", "Instance"},
    MemStorageService = {"MemStorageService", "Instance"},
    NetworkClient = {"NetworkClient", "Instance"},
    ClientReplicator = {"ClientReplicator", "Instance"},
}
local function classIsA(className, targetClass)
    if className == targetClass then return true end
    local parents = classParents[className] or {className, "Instance"}
    for _, parentName in ipairsFunction(parents) do
        if parentName == targetClass then return true end
    end
    return false
end
local uiNamingConvention = {
    {pattern = "window", prefix = "Window", counter = "window"},
    {pattern = "tab", prefix = "Tab", counter = "tab"},
    {pattern = "section", prefix = "Section", counter = "section"},
    {pattern = "button", prefix = "Button", counter = "button"},
    {pattern = "toggle", prefix = "Toggle", counter = "toggle"},
    {pattern = "slider", prefix = "Slider", counter = "slider"},
    {pattern = "dropdown", prefix = "Dropdown", counter = "dropdown"},
    {pattern = "textbox", prefix = "Textbox", counter = "textbox"},
    {pattern = "input", prefix = "Input", counter = "input"},
    {pattern = "label", prefix = "Label", counter = "label"},
    {pattern = "keybind", prefix = "Keybind", counter = "keybind"},
    {pattern = "colorpicker", prefix = "ColorPicker", counter = "colorpicker"},
    {pattern = "paragraph", prefix = "Paragraph", counter = "paragraph"},
    {pattern = "notification", prefix = "Notification", counter = "notification"},
    {pattern = "divider", prefix = "Divider", counter = "divider"},
    {pattern = "bind", prefix = "Bind", counter = "bind"},
    {pattern = "picker", prefix = "Picker", counter = "picker"}
}
local uiCounters = {}
local function getUiCounter(name)
    uiCounters[name] = (uiCounters[name] or 0) + 1
    return uiCounters[name]
end
local function resolveVariableName(obj, originalName, hintString)
    if not obj then
        obj = "var"
    end
    local formattedName = formatValue(obj)
    if serviceShortcuts[formattedName] then
        return serviceShortcuts[formattedName]
    end
    if hintString then
        local lowerHint = hintString:lower()
        for _, patternEntry in ipairsFunction(uiNamingConvention) do
            if lowerHint:find(patternEntry.pattern) then
                local counter = getUiCounter(patternEntry.counter)
                return counter == 1 and patternEntry.prefix or patternEntry.prefix .. counter
            end
        end
    end
    if formattedName == "LocalPlayer" then
        return "LocalPlayer"
    end
    if formattedName == "Character" then
        return "Character"
    end
    if formattedName == "Humanoid" then
        return "Humanoid"
    end
    if formattedName == "HumanoidRootPart" then
        return "HumanoidRootPart"
    end
    if formattedName == "Camera" then
        return "Camera"
    end
    if formattedName:match("^Enum%.") then
        return formattedName
    end
    local sanitizedName = formattedName:gsub("[^%w_]", '"'):gsub("^%d+", '"')
    if sanitizedName == '"' or sanitizedName == "Object" or sanitizedName == "Value" or sanitizedName == "result" then
        sanitizedName = "var"
    end
    return sanitizedName
end
local function registerVariable(obj, objName, varType, hintString)
    local existing = dumperState.registry[obj]
    if existing and existing:match("^v%d+$") then
        return existing
    end
    dumperState.ls_counter = (dumperState.ls_counter or 0) + 1
    local newName = "v" .. dumperState.ls_counter
    dumperState.names_used[newName] = true
    dumperState.registry[obj] = newName
    dumperState.reverse_registry[newName] = obj
    dumperState.variable_types[newName] = varType or typeFunction(obj)
    return newName
end
local function serializeValue(obj, depth, visited, allowInline)
    depth = depth or 0
    visited = visited or {}
    if depth > configuration.MAX_DEPTH then
        return "{ --[[max depth]] }"
    end
    local valueType = typeFunction(obj)
    if isProxyTable(obj) then
        local proxyValue = rawget(obj, "__value")
        return toStringFunction(proxyValue or 0)
    end
    if valueType == "table" and dumperState.registry[obj] then
        return dumperState.registry[obj]
    end
    if valueType == "nil" then
        return "nil"
    elseif valueType == "string" then
        if #obj > 100 and obj:match("^[A-Za-z0-9+/=]+$") then
            table.insert(dumperState.string_refs, {value = obj:sub(1, 50) .. "...", hint = "base64", full_length = #obj})
        elseif obj:match("https?://") then
            table.insert(dumperState.string_refs, {value = obj, hint = "URL"})
        elseif obj:match("rbxasset://") or obj:match("rbxassetid://") then
            table.insert(dumperState.string_refs, {value = obj, hint = "Asset"})
        end
        return formatStringLiteral(obj)
    elseif valueType == "number" then
        if obj ~= obj then
            return "0/0"
        end
        if obj == math.huge then
            return "math.huge"
        end
        if obj == -math.huge then
            return "-math.huge"
        end
        if obj == math.floor(obj) then
            return toStringFunction(math.floor(obj))
        end
        return string.format("%.6g", obj)
    elseif valueType == "boolean" then
        return toStringFunction(obj)
    elseif valueType == "function" then
        if dumperState.registry[obj] then
            return dumperState.registry[obj]
        end
        return "function() end"
    elseif valueType == "table" then
        if isProxy(obj) then
            return dumperState.registry[obj] or "proxy"
        end
        if visited[obj] then
            return "{ --[[circular]] }"
        end
        visited[obj] = true
        local count = 0
        for k, v in pairsFunction(obj) do
            if k ~= proxyList and k ~= "__proxy_id" then
                count = count + 1
            end
        end
        if count == 0 then
            return "{}"
        end
        local isSequence = true
        local maxIdx = 0
        for k, v in pairsFunction(obj) do
            if k ~= proxyList and k ~= "__proxy_id" then
                if typeFunction(k) ~= "number" or k < 1 or k ~= math.floor(k) then
                    isSequence = false
                    break
                else
                    maxIdx = math.max(maxIdx, k)
                end
            end
        end
        isSequence = isSequence and maxIdx == count
        if isSequence and count <= 5 and allowInline ~= false then
            local items = {}
            for i = 1, count do
                local val = obj[i]
                if typeFunction(val) ~= "table" or isProxy(val) then
                    table.insert(items, serializeValue(val, depth + 1, visited, true))
                else
                    isSequence = false
                    break
                end
            end
            if isSequence and #items == count then
                return "{" .. table.concat(items, ", ") .. "}"
            end
        end
        local output = {}
        local itemCount = 0
        local indent = string.rep("    ", dumperState.indent + depth + 1)
        local baseIndent = string.rep("    ", dumperState.indent + depth)
        for k, v in pairsFunction(obj) do
            if k ~= proxyList and k ~= "__proxy_id" then
                itemCount = itemCount + 1
                if itemCount > configuration.MAX_TABLE_ITEMS then
                    table.insert(output, indent .. "-- ..." .. count - itemCount + 1 .. " more")
                    break
                end
                local keyStr
                if isSequence then
                    keyStr = nil
                elseif typeFunction(k) == "string" and k:match("^[%a_][%w_]*$") then
                    keyStr = k
                else
                    keyStr = "[" .. serializeValue(k, depth + 1, visited) .. "]"
                end
                local valStr = serializeValue(v, depth + 1, visited)
                if keyStr then
                    table.insert(output, indent .. keyStr .. " = " .. valStr)
                else
                    table.insert(output, indent .. valStr)
                end
            end
        end
        if #output == 0 then
            return "{}"
        end
        return "{\n" .. table.concat(output, ",\n") .. "\n" .. baseIndent .. "}"
    elseif valueType == "userdata" then
        if dumperState.registry[obj] then
            return dumperState.registry[obj]
        end
        local success, result = pcallFunction(toStringFunction, obj)
        return success and result or "userdata"
    elseif valueType == "thread" then
        return "coroutine.create(function() end)"
    else
        local success, result = pcallFunction(toStringFunction, obj)
        return success and result or "nil"
    end
end
local proxyStore = {}
setmetatable(proxyStore, {__mode = "k"})
local function createProxy()
    local proxy = {}
    proxyStore[proxy] = true
    local meta = {}
    setmetatable(proxy, meta)
    return proxy, meta
end
local function isProxy(obj)
    return proxyStore[obj] == true
end
local createProxyObject
local createProxyMethod
-- ContentId type for AT6 (SurfaceAppearance.ColorMap etc)
local function _makeContentId(val)
    val = val or ""
    return setmetatable({_value = val}, {
        __typeof = "ContentId",
        __tostring = function() return val end,
        __eq = function(a, b)
            local av = typeFunction(a) == "table" and rawget(a, "_value") or a
            local bv = typeFunction(b) == "table" and rawget(b, "_value") or b
            return av == bv
        end,
        __index = function(t, k) if k == "_value" then return val end end,
    })
end
local _makeVector3
local _makeCFrame
local function createProxyInstance(bm)
    local proxy, meta = createProxy()
    rawset(proxy, proxyMarker, true)
    rawset(proxy, "__value", bm)
    dumperState.registry[proxy] = toStringFunction(bm)
    meta.__tostring = function() return toStringFunction(bm) end
    meta.__index = function(tbl, key)
        if key == proxyList or key == "__proxy_id" or key == proxyMarker or key == "__value" then
            return rawget(tbl, key)
        end
        return createProxyInstance(0)
    end
    meta.__newindex = function() end
    meta.__call = function() return bm end
    local function op(symbol)
        return function(a, b)
            local valA = typeFunction(a) == "table" and rawget(a, "__value") or a or 0
            local valB = typeFunction(b) == "table" and rawget(b, "__value") or b or 0
            local res
            if symbol == "+" then res = valA + valB
            elseif symbol == "-" then res = valA - valB
            elseif symbol == "*" then res = valA * valB
            elseif symbol == "/" then res = valB ~= 0 and valA / valB or 0
            elseif symbol == "%" then res = valB ~= 0 and valA % valB or 0
            elseif symbol == "^" then res = valA ^ valB
            else res = 0 end
            return createProxyInstance(res)
        end
    end
    meta.__add = op("+")
    meta.__sub = op("-")
    meta.__mul = op("*")
    meta.__div = op("/")
    meta.__mod = op("%")
    meta.__pow = op("^")
    meta.__unm = function(a) return createProxyInstance(-(rawget(a, "__value") or 0)) end
    meta.__eq = function(a, b)
        local valA = typeFunction(a) == "table" and rawget(a, "__value") or a
        local valB = typeFunction(b) == "table" and rawget(b, "__value") or b
        return valA == valB
    end
    meta.__lt = function(a, b)
        local valA = typeFunction(a) == "table" and rawget(a, "__value") or a
        local valB = typeFunction(b) == "table" and rawget(b, "__value") or b
        return valA < valB
    end
    meta.__le = function(a, b)
        local valA = typeFunction(a) == "table" and rawget(a, "__value") or a
        local valB = typeFunction(b) == "table" and rawget(b, "__value") or b
        return valA <= valB
    end
    meta.__len = function() return 0 end
    return proxy
end
local function executeFunction(func, args)
    if typeFunction(func) ~= "function" then
        return {}
    end
    local outputCount = #dumperState.output
    local previousIteratorState = dumperState.pending_iterator
    dumperState.pending_iterator = false
    xpcallFunction( function() func(table.unpack(args or {})) end, function() end )
    while dumperState.pending_iterator do
        dumperState.indent = dumperState.indent - 1
        emitOutput("end")
        dumperState.pending_iterator = false
    end
    dumperState.pending_iterator = previousIteratorState
    local capturedLines = {}
    for i = outputCount + 1, #dumperState.output do
        table.insert(capturedLines, dumperState.output[i])
    end
    for i = #dumperState.output, outputCount + 1, -1 do
        table.remove(dumperState.output, i)
    end
    return capturedLines
end
createProxyMethod = function(methodName, parentProxy)
    local proxy, meta = createProxy()
    rawset(proxy, "__is_method", true)
    local parentName = dumperState.registry[parentProxy] or "object"
    local methodSignature = formatValue(methodName)
    dumperState.registry[proxy] = parentName .. "." .. methodSignature
    meta.__call = function(self, firstArg, ...)
        local args
        if firstArg == proxy or firstArg == parentProxy or isProxy(firstArg) then
            args = {...}
        else
            args = {firstArg, ...}
        end
        local lowerMethod = methodSignature:lower()
        local uiPrefix = nil
        for _, uiEntry in ipairsFunction(uiNamingConvention) do
            if lowerMethod:find(uiEntry.pattern) then
                uiPrefix = uiEntry.prefix
                break
            end
        end
        local callbackFunc, callbackKey, callbackIndex = nil, nil, nil
        for i, val in ipairsFunction(args) do
            if typeFunction(val) == "function" then
                callbackFunc = val
                break
            elseif typeFunction(val) == "table" and not isProxy(val) then
                for k, v in pairsFunction(val) do
                    local keyStr = toStringFunction(k):lower()
                    if keyStr == "callback" and typeFunction(v) == "function" then
                        callbackFunc = v
                        callbackKey = k
                        callbackIndex = i
                        break
                    end
                end
            end
        end
        local defaultParam, dummyArgs = "value", {}
        if callbackFunc then
            if lowerMethod:match("toggle") then
                defaultParam = "enabled"
                dummyArgs = {true}
            elseif lowerMethod:match("slider") then
                defaultParam = "value"
                dummyArgs = {50}
            elseif lowerMethod:match("dropdown") then
                defaultParam = "selected"
                dummyArgs = {"Option"}
            elseif lowerMethod:match("textbox") or lowerMethod:match("input") then
                defaultParam = "text"
                dummyArgs = {inputKey or "input"}
            elseif lowerMethod:match("keybind") or lowerMethod:match("bind") then
                defaultParam = "key"
                dummyArgs = {createProxyObject("Enum.KeyCode.E", false)}
            elseif lowerMethod:match("color") then
                defaultParam = "color"
                dummyArgs = {Color3.fromRGB(255, 255, 255)}
            elseif lowerMethod:match("button") then
                defaultParam = ""
                dummyArgs = {}
            end
        end
        local callbackLines = {}
        if callbackFunc then
            callbackLines = executeFunction(callbackFunc, dummyArgs)
        end
        local newProxy = createProxyObject(uiPrefix or methodSignature, false, parentProxy)
        local varName = registerVariable(newProxy, uiPrefix or methodSignature, nil, methodSignature)
        local argStrings = {}
        for i, val in ipairsFunction(args) do
            if typeFunction(val) == "table" and not isProxy(val) and i == callbackIndex then
                local tableParts = {}
                for k, v in pairsFunction(val) do
                    local keyStr
                    if typeFunction(k) == "string" and k:match("^[%a_][%w_]*$") then
                        keyStr = k
                    else
                        keyStr = "[" .. serializeValue(k) .. "]"
                    end
                    if k == callbackKey and #callbackLines > 0 then
                        local funcSignature = defaultParam ~= '"' and "function(" .. "bI" .. ")" or "function()"
                        local indent = string.rep("    ", dumperState.indent + 2)
                        local funcBody = {}
                        for _, line in ipairsFunction(callbackLines) do
                            table.insert(funcBody, indent .. (line:match("^%s*(.*)$") or line))
                        end
                        local baseIndent = string.rep("    ", dumperState.indent + 1)
                        table.insert(tableParts, keyStr .. " = " .. funcSignature .. "\n" .. table.concat(funcBody, "\n") .. "\n" .. baseIndent .. "end")
                    elseif k == callbackKey then
                        local funcDef = defaultParam ~= "" and "function(" .. defaultParam .. ") end" or "function() end"
                        table.insert(tableParts, keyStr .. " = " .. funcDef)
                    else
                        table.insert(tableParts, keyStr .. " = " .. serializeValue(v))
                    end
                end
                table.insert(argStrings, "{\n" .. string.rep("    ", dumperState.indent + 1) .. table.concat(tableParts, ",\n" .. string.rep("    ", dumperState.indent + 1)) .. "\n" .. string.rep("    ", dumperState.indent) .. "}")
            elseif typeFunction(val) == "function" then
                if #callbackLines > 0 then
                    local funcSignature = defaultParam ~= '"' and "function(" .. defaultParam .. ")" or "function()"
                    local indent = string.rep("    ", dumperState.indent + 1)
                    local funcBody = {}
                    for _, line in ipairsFunction(callbackLines) do
                        table.insert(funcBody, indent .. (line:match("^%s*(.*)$") or line))
                    end
                    table.insert(argStrings, funcSignature .. "\n" .. table.concat(funcBody, "\n") .. "\n" .. string.rep("    ", dumperState.indent) .. "end")
                else
                    local funcDef = defaultParam ~= '"' and "function(" .. defaultParam .. ") end" or "function() end"
                    table.insert(argStrings, funcDef)
                end
            else
                table.insert(argStrings, serializeValue(val))
            end
        end
        emitOutput(string.format("local %s = %s:%s(%s)", varName, parentName, methodSignature, table.concat(argStrings, ", ")))
        return newProxy
    end
    meta.__index = function(tbl, key)
        if key == proxyList or key == "__proxy_id" then
            return rawget(tbl, key)
        end
        return createProxyMethod(key, proxy)
    end
    meta.__tostring = function() return parentName .. ":" .. methodSignature end
    meta.__index = function(tbl, key)
        local chainName = (dumperState.registry[proxy] or methodSignature) .. "." .. tostring(key)
        local childProxy = createProxyObject(key, false, nil)
        dumperState.registry[childProxy] = chainName
        local knownClassNames = {
            SetBlockedUserIdsRequest = "RemoteEvent",
            AtomicBinding = "BindableEvent",
        }
        if knownClassNames[key] then
            dumperState.property_store[childProxy] = dumperState.property_store[childProxy] or {}
            dumperState.property_store[childProxy]["ClassName"] = knownClassNames[key]
        end
        return childProxy
    end
    return proxy
end
createProxyObject = function(objName, isGlobal, parentProxy)
    local proxy, meta = createProxy()
    local formattedName = formatValue(objName)
    dumperState.property_store[proxy] = {}
    if isGlobal then
        dumperState.registry[proxy] = formattedName
        dumperState.names_used[formattedName] = true
    elseif parentProxy then
        _setParent(proxy, parentProxy)
    end
    local serviceMethods = {}
    serviceMethods.GetService = function(self, serviceName)
        local resolvedName = formatValue(serviceName)
        -- strip null bytes (anti-tamper trick)
        resolvedName = string.gsub(resolvedName, "%z", "")
        if resolvedName == "Workspace" then
            return workspace
        end
        if not serviceNames[resolvedName] or resolvedName == "DebuggerManager" then
            errorFunction("Service not available", 0)
        end
        local serviceProxy = _at.svcCache[resolvedName]
        if not serviceProxy then
            serviceProxy = createProxyObject(resolvedName, false, self)
            _at.svcCache[resolvedName] = serviceProxy
            dumperState.parent_map[serviceProxy] = game
            dumperState.property_store[serviceProxy] = dumperState.property_store[serviceProxy] or {}
            dumperState.property_store[serviceProxy].ClassName = resolvedName
            dumperState.property_store[serviceProxy].Name = resolvedName
            if resolvedName == "CaptureService" then
                _at.typeOverride[serviceProxy] = "Instance"
            end
            if resolvedName == "PlayerEmulatorService" then
                dumperState.property_store[serviceProxy].PlayerEmulationEnabled = false
            end
            if resolvedName == "CorePackages" or resolvedName == "RobloxReplicatedStorage" or resolvedName == "RobloxGui" then
                -- infinite deep proxy: any property path always returns a truthy proxy
                local function _makeDeepProxy(name)
                    local _dp = {}
                    setmetatable(_dp, {
                        __index = function(_, k)
                            return _makeDeepProxy(name .. "." .. tostring(k))
                        end,
                        __tostring = function() return name end,
                        __call = function(_, ...) return _makeDeepProxy(name .. "()") end,
                        __len = function() return 0 end,
                        __newindex = function() end,
                    })
                    return _dp
                end
                _at.typeOverride[serviceProxy] = "Instance"
                dumperState.property_store[serviceProxy].__deepProxy = _makeDeepProxy(resolvedName)
                local _dpMeta = debug and debug.getmetatable and debug.getmetatable(serviceProxy) or getmetatable(serviceProxy)
                if type(_dpMeta) == "table" then
                    local _prevDpIdx = _dpMeta.__index
                    _dpMeta.__index = function(tbl, key)
                        if key == proxyList or key == "__proxy_id" then return rawget(tbl, key) end
                        local _dp = dumperState.property_store[serviceProxy] and dumperState.property_store[serviceProxy].__deepProxy
                        if _dp then
                            local function _makeDeepProxyInner(n)
                                local d = {}
                                setmetatable(d, {
                                    __index = function(_, k) return _makeDeepProxyInner(n.."."..tostring(k)) end,
                                    __tostring = function() return n end,
                                    __call = function(_, ...) return _makeDeepProxyInner(n.."()") end,
                                    __len = function() return 0 end,
                                    __newindex = function() end,
                                })
                                return d
                            end
                            return _makeDeepProxyInner(resolvedName.."."..tostring(key))
                        end
                        if type(_prevDpIdx) == "function" then return _prevDpIdx(tbl, key) end
                        if type(_prevDpIdx) == "table" then return _prevDpIdx[key] end
                        return nil
                    end
                end
            end
        end
        local varName = registerVariable(serviceProxy, resolvedName)
        local parentPath = dumperState.registry[self] or "game"
        emitOutput(string.format("local %s = %s:GetService(%s)", varName, parentPath, formatStringLiteral(resolvedName)))
        return serviceProxy
    end
    serviceMethods.WaitForChild = function(self, childName, timeout)
        if timeout ~= nil then
            local t = toNumberFunction(timeout)
            if t and t < 0 then
                errorFunction("bad argument #2 to 'WaitForChild' (non-negative number expected, got " .. toStringFunction(t) .. ")", 2)
            end
        end
        local resolvedName = formatValue(childName)
        local childProxy = createProxyObject(resolvedName, false, self)
        local varName = registerVariable(childProxy, resolvedName)
        local parentPath = dumperState.registry[self] or "object"
        if timeout then
            emitOutput(string.format("local %s = %s:WaitForChild(%s, %s)", varName, parentPath, formatStringLiteral(resolvedName), serializeValue(timeout)))
        else
            emitOutput(string.format("local %s = %s:WaitForChild(%s)", varName, parentPath, formatStringLiteral(resolvedName)))
        end
        return childProxy
    end
    serviceMethods.FindFirstChild = function(self, childName, recursive)
        if recursive ~= nil and typeFunction(recursive) ~= "boolean" then
            errorFunction("bad argument #2 to 'FindFirstChild' (boolean expected, got " .. typeFunction(recursive) .. ")", 2)
        end
        local resolvedName = formatValue(childName)
        for _, child in ipairsFunction(_at.children[self] or {}) do
            local props = dumperState.property_store[child] or {}
            if props.Name == resolvedName or dumperState.registry[child] == resolvedName then
                return child
            end
        end
        if recursive then
            for _, child in ipairsFunction(_getAllDescendants(self, {})) do
                local props = dumperState.property_store[child] or {}
                if props.Name == resolvedName or dumperState.registry[child] == resolvedName then
                    return child
                end
            end
        end
        local childProxy = createProxyObject(resolvedName, false, self)
        local varName = registerVariable(childProxy, resolvedName)
        local parentPath = dumperState.registry[self] or "object"
        if recursive then
            emitOutput(string.format("local %s = %s:FindFirstChild(%s, true)", varName, parentPath, formatStringLiteral(resolvedName)))
        else
            emitOutput(string.format("local %s = %s:FindFirstChild(%s)", varName, parentPath, formatStringLiteral(resolvedName)))
        end
        return childProxy
    end
    serviceMethods.FindFirstChildOfClass = function(self, className)
        local resolvedName = formatValue(className)
        for _, child in ipairsFunction(_at.children[self] or {}) do
            local props = dumperState.property_store[child] or {}
            local cn = props.ClassName or ""
            if cn == resolvedName then return child end
        end
        local newProxy = createProxyObject(resolvedName, false, self)
        local varName = registerVariable(newProxy, resolvedName)
        local parentPath = dumperState.registry[self] or "object"
        emitOutput(string.format("local %s = %s:FindFirstChildOfClass(%s)", varName, parentPath, formatStringLiteral(resolvedName)))
        return newProxy
    end
    local _classInherits = {
        Part = {"Part","BasePart","PVInstance","Instance"},
        MeshPart = {"MeshPart","BasePart","PVInstance","Instance"},
        UnionOperation = {"UnionOperation","BasePart","PVInstance","Instance"},
        WedgePart = {"WedgePart","BasePart","PVInstance","Instance"},
        SpecialMesh = {"SpecialMesh","DataModelMesh","Instance"},
        Humanoid = {"Humanoid","Instance"},
        LocalScript = {"LocalScript","BaseScript","LuaSourceContainer","Instance"},
        Script = {"Script","BaseScript","LuaSourceContainer","Instance"},
        ModuleScript = {"ModuleScript","LuaSourceContainer","Instance"},
        Folder = {"Folder","Instance"},
        Model = {"Model","PVInstance","Instance"},
        Frame = {"Frame","GuiObject","GuiBase2d","Instance"},
        TextLabel = {"TextLabel","TextBase","GuiObject","GuiBase2d","Instance"},
        TextButton = {"TextButton","TextBase","GuiButton","GuiObject","GuiBase2d","Instance"},
        TextBox = {"TextBox","TextBase","GuiObject","GuiBase2d","Instance"},
        ImageLabel = {"ImageLabel","GuiObject","GuiBase2d","Instance"},
        ImageButton = {"ImageButton","GuiButton","GuiObject","GuiBase2d","Instance"},
        ScreenGui = {"ScreenGui","LayerCollector","GuiBase","Instance"},
        RemoteEvent = {"RemoteEvent","Instance"},
        RemoteFunction = {"RemoteFunction","Instance"},
        BindableEvent = {"BindableEvent","Instance"},
        BindableFunction = {"BindableFunction","Instance"},
        LocalizationTable = {"LocalizationTable","Instance"},
        Translator = {"Translator","Instance"},
    }
    local function _isA(childClass, targetClass)
        if childClass == targetClass then return true end
        local hierarchy = _classInherits[childClass]
        if hierarchy then
            for _, base in ipairsFunction(hierarchy) do
                if base == targetClass then return true end
            end
        end
        return false
    end
    serviceMethods.FindFirstChildWhichIsA = function(self, className)
        local resolvedName = formatValue(className)
        for _, child in ipairsFunction(_at.children[self] or {}) do
            local props = dumperState.property_store[child] or {}
            local cn = props.ClassName or ""
            if _isA(cn, resolvedName) then return child end
        end
        local newProxy = createProxyObject(resolvedName, false, self)
        local varName = registerVariable(newProxy, resolvedName)
        local parentPath = dumperState.registry[self] or "object"
        emitOutput(string.format("local %s = %s:FindFirstChildWhichIsA(%s)", varName, parentPath, formatStringLiteral(resolvedName)))
        return newProxy
    end
    serviceMethods.FindFirstAncestor = function(self, ancestorName)
        local resolvedName = formatValue(ancestorName)
        local proxy = createProxyObject(resolvedName, false, proxy)
        local varName = registerVariable(proxy, resolvedName)
        local parentPath = dumperState.registry[proxy] or "object"
        emitOutput(string.format("local %s = %s:FindFirstAncestor(%s)", varName, parentPath, formatStringLiteral(resolvedName)))
        return proxy
    end
    serviceMethods.FindFirstAncestorOfClass = function(self, className)
        local resolvedName = formatValue(className)
        local proxy = createProxyObject(resolvedName, false, proxy)
        local varName = registerVariable(proxy, resolvedName)
        local parentPath = dumperState.registry[proxy] or "object"
        emitOutput(string.format("local %s = %s:FindFirstAncestorOfClass(%s)", varName, parentPath, formatStringLiteral(resolvedName)))
        return proxy
    end
    serviceMethods.FindFirstAncestorWhichIsA = function(self, className)
        local resolvedName = formatValue(className)
        local proxy = createProxyObject(resolvedName, false, proxy)
        local varName = registerVariable(proxy, resolvedName)
        local parentPath = dumperState.registry[proxy] or "object"
        emitOutput(string.format("local %s = %s:FindFirstAncestorWhichIsA(%s)", varName, parentPath, formatStringLiteral(resolvedName)))
        return proxy
    end
    serviceMethods.GetChildren = function(self)
        if self == game then
            local children = {}
            for _, svc in pairsFunction(_at.svcCache) do
                children[#children + 1] = svc
            end
            return children
        end
        return {}
    end
    serviceMethods.GetDescendants = function(self)
        local parentPath = dumperState.registry[proxy] or "object"
        emitOutput(string.format("for _, obj in %s:GetDescendants() do", parentPath))
        dumperState.indent = dumperState.indent + 1
        local descProxy = createProxyObject("obj", false)
        dumperState.registry[descProxy] = "obj"
        dumperState.property_store[descProxy] = {Name = "Ball", ClassName = "Part", Size = Vector3.new(1, 1, 1)}
        local yielded = false
        return function()
            if not yielded then
                yielded = true
                return 1, descProxy
            else
                dumperState.indent = dumperState.indent - 1
                emitOutput("end")
                return nil
            end
        end, nil, 0
    end
    serviceMethods.Clone = function(self)
        local props = dumperState.property_store[proxy] or {}
        if props.Archivable == false then return nil end
        local parentPath = dumperState.registry[proxy] or "object"
        local cloneProxy = createProxyObject((formattedName or "object") .. "Clone", false)
        local varName = registerVariable(cloneProxy, (formattedName or "object") .. "Clone")
        emitOutput(string.format("local %s = %s:Clone()", varName, parentPath))
        dumperState.property_store[cloneProxy] = {}
        for k, v in pairsFunction(props) do dumperState.property_store[cloneProxy][k] = v end
        return cloneProxy
    end
    -- LocalizationTable entry store keyed by proxy
    if not _at.locEntries then _at.locEntries = {} end
    serviceMethods.SetEntries = function(self, entries)
        _at.locEntries[proxy] = entries or {}
    end
    serviceMethods.GetEntries = function(self)
        return _at.locEntries[proxy] or {}
    end
    serviceMethods.GetEntry = function(self, key)
        local store = _at.locEntries[proxy] or {}
        for _, e in ipairs(store) do
            if e.Key == key then return e end
        end
        return nil
    end
    serviceMethods.RemoveEntry = function(self, key)
        local store = _at.locEntries[proxy] or {}
        for i, e in ipairs(store) do
            if e.Key == key then table.remove(store, i) return end
        end
    end
    serviceMethods.GetTranslator = function(self, locale)
        local translator = createProxyObject("Translator", false)
        dumperState.property_store[translator] = {ClassName = "Translator", LocaleId = locale or "en"}
        return translator
    end
    serviceMethods.Destroy = function(self)
        local parentPath = dumperState.registry[proxy] or "object"
        -- recursively destroy all descendants first
        local function destroyRec(p)
            local kids = _at.children[p] or {}
            for i = #kids, 1, -1 do
                local child = kids[i]
                destroyRec(child)
                dumperState.parent_map[child] = nil
                if dumperState.property_store[child] then
                    dumperState.property_store[child].Parent = nil
                end
            end
            _at.children[p] = {}
        end
        destroyRec(proxy)
        _setParent(proxy, nil)
        if dumperState.property_store[proxy] then
            dumperState.property_store[proxy].Parent = nil
        end
        emitOutput(string.format("%s:Destroy()", parentPath))
    end
    serviceMethods.ApplyAngularImpulse = function(self, impulse)
        -- store impulse so AssemblyAngularVelocity returns something meaningful
        dumperState.property_store[proxy] = dumperState.property_store[proxy] or {}
        dumperState.property_store[proxy]["_angularImpulse"] = impulse
        local path = dumperState.registry[proxy] or "part"
        emitOutput(string.format("%s:ApplyAngularImpulse(%s)", path, serializeValue(impulse)))
    end
    serviceMethods.ApplyImpulse = function(self, impulse)
        local path = dumperState.registry[proxy] or "part"
        emitOutput(string.format("%s:ApplyImpulse(%s)", path, serializeValue(impulse)))
    end
    serviceMethods.GetPartBoundsInBox = function(self, cf, size, params)
        -- return all workspace children that aren't in the exclude list
        local excluded = {}
        if params and typeFunction(params) == "table" and params.FilterDescendantsInstances then
            for _, inst in ipairsFunction(params.FilterDescendantsInstances) do
                excluded[inst] = true
            end
        end
        local results = {}
        -- walk workspace children from parent_map
        for child, parent in pairsFunction(dumperState.parent_map) do
            if parent == workspace and not excluded[child] then
                table.insert(results, child)
            end
        end
        return results
    end
    serviceMethods.GetPartBoundsInRadius = function(self, position, radius, params)
        return serviceMethods.GetPartBoundsInBox(self, CFrame.new(position), Vector3.new(radius*2,radius*2,radius*2), params)
    end
    serviceMethods.ClearAllChildren = function(self)
        local parentPath = dumperState.registry[proxy] or "object"
        local function clearRec(p)
            local kids = _at.children[p] or {}
            for i = #kids, 1, -1 do
                local child = kids[i]
                clearRec(child)
                dumperState.parent_map[child] = nil
                if dumperState.property_store[child] then
                    dumperState.property_store[child].Parent = nil
                end
            end
            _at.children[p] = {}
        end
        clearRec(proxy)
        emitOutput(string.format("%s:ClearAllChildren()", parentPath))
    end
    serviceMethods.Connect = function(self, func)
        local signalPath = dumperState.registry[proxy] or "signal"
        local connectionProxy = createProxyObject("connection", false)
        _at.typeOverride[connectionProxy] = "RBXScriptConnection"
        _at.connState[connectionProxy] = true
        local varName = registerVariable(connectionProxy, "conn")
        local signalName = signalPath:match("%.([^%.]+)$") or signalPath
        -- AT5: store live callback for ChildAdded/DescendantAdded
        local ownerProxy = (_at.signalOwner and _at.signalOwner[proxy]) or dumperState.parent_map[proxy] or proxy
        if (signalName == "ChildAdded" or signalName == "DescendantAdded") and typeFunction(func) == "function" then
            _at.signalCallbacks[ownerProxy] = _at.signalCallbacks[ownerProxy] or {}
            _at.signalCallbacks[ownerProxy][signalName] = _at.signalCallbacks[ownerProxy][signalName] or {}
            local cbList = _at.signalCallbacks[ownerProxy][signalName]
            cbList[#cbList+1] = func
            _at.connState[connectionProxy] = {list=cbList, func=func}
        end
        local args = {"..."}
        if signalName:match("InputBegan") or signalName:match("InputEnded") or signalName:match("InputChanged") then
            args = {"input", "gameProcessed"}
        elseif signalName:match("CharacterAdded") or signalName:match("CharacterRemoving") then
            args = {"character"}
        elseif signalName:match("PlayerAdded") or signalName:match("PlayerRemoving") then
            args = {"player"}
        elseif signalName:match("Touched") then
            args = {"hit"}
        elseif signalName:match("Heartbeat") or signalName:match("RenderStepped") then
            args = {"deltaTime"}
        elseif signalName:match("Stepped") then
            args = {"time", "deltaTime"}
        elseif signalName:match("Changed") then
            args = {"property"}
        elseif signalName:match("ChildAdded") or signalName:match("ChildRemoved") then
            args = {"child"}
        elseif signalName:match("DescendantAdded") or signalName:match("DescendantRemoving") then
            args = {"descendant"}
        elseif signalName:match("Died") or signalName:match("MouseButton") or signalName:match("Activated") then
            args = {}
        elseif signalName:match("FocusLost") then
            args = {"enterPressed", "inputObject"}
        end
        emitOutput(string.format("local %s = %s:Connect(function(%s)", varName, signalPath, table.concat(args, ", ")))
        dumperState.indent = dumperState.indent + 1
        if typeFunction(func) == "function" then
            if signalName:match("Heartbeat") or signalName:match("RenderStepped") then
                -- use coroutine to defer so connectionProxy is returned first
                -- meaning conn local in script is assigned before callbacks fire
                local _connProxy = connectionProxy
                local _co = coroutine.create(function()
                    coroutine.yield() -- yield once, resumed after return connectionProxy
                    local _dts = {
                        0.016 + math.random()*0.003,
                        0.014 + math.random()*0.003,
                        0.017 + math.random()*0.003,
                        0.013 + math.random()*0.003,
                        0.015 + math.random()*0.003,
                    }
                    xpcallFunction(function()
                        for i = 1, 5 do
                            if _at.connState[_connProxy] == false then break end
                            func(_dts[i])
                        end
                    end, function() end)
                end)
                coroutine.resume(_co)
                -- store co to resume after return
                _at.pendingHeartbeat = _at.pendingHeartbeat or {}
                table.insert(_at.pendingHeartbeat, _co)
            elseif signalName:match("Stepped") then
                xpcallFunction( function() for i = 1, 5 do func(osLibrary.clock(), 0.015 + i * 0.001) end end, function() end )
            elseif signalName:match("^Error$") then
            elseif signalName == "ChildAdded" or signalName == "DescendantAdded"
                or signalName == "ChildRemoved" or signalName == "DescendantRemoving" then
                -- handled live via _setParent, don't fire immediately
            else
                xpcallFunction( function() func() end, function() end )
            end
        end
        while dumperState.pending_iterator do
            dumperState.indent = dumperState.indent - 1
            emitOutput("end")
            dumperState.pending_iterator = false
        end
        dumperState.indent = dumperState.indent - 1
        emitOutput("end)")
        return connectionProxy
    end
    serviceMethods.Once = function(self, func)
        local signalPath = dumperState.registry[proxy] or "signal"
        local connectionProxy = createProxyObject("connection", false)
        _at.typeOverride[connectionProxy] = "RBXScriptConnection"
        _at.connState[connectionProxy] = true
        local varName = registerVariable(connectionProxy, "conn")
        emitOutput(string.format("local %s = %s:Once(function(...)", varName, signalPath))
        dumperState.indent = dumperState.indent + 1
        if typeFunction(func) == "function" then
            xpcallFunction( function() func() end, function() end )
        end
        dumperState.indent = dumperState.indent - 1
        emitOutput("end)")
        return connectionProxy
    end
    serviceMethods.ConnectParallel = function(self, func)
        local signalPath = dumperState.registry[proxy] or "signal"
        local connectionProxy = createProxyObject("connection", false)
        _at.typeOverride[connectionProxy] = "RBXScriptConnection"
        _at.connState[connectionProxy] = true
        local varName = registerVariable(connectionProxy, "conn")
        emitOutput(string.format("local %s = %s:ConnectParallel(function(...)", varName, signalPath))
        dumperState.indent = dumperState.indent + 1
        if typeFunction(func) == "function" then
            xpcallFunction( function() func() end, function() end )
        end
        dumperState.indent = dumperState.indent - 1
        emitOutput("end)")
        return connectionProxy
    end
    serviceMethods.Wait = function(self)
        local signalPath = dumperState.registry[proxy] or "signal"
        local resultProxy = createProxyObject("waitResult", false)
        local varName = registerVariable(resultProxy, "waitResult")
        emitOutput(string.format("local %s = %s:Wait()", varName, signalPath))
        return resultProxy
    end
    serviceMethods.Disconnect = function(self)
        local connectionPath = dumperState.registry[proxy] or "connection"
        -- remove live callback if registered
        local state = _at.connState[proxy]
        if typeFunction(state) == "table" and state.list and state.func then
            for i = #state.list, 1, -1 do
                if state.list[i] == state.func then table.remove(state.list, i) end
            end
        end
        _at.connState[proxy] = false
        emitOutput(string.format("%s:Disconnect()", connectionPath))
    end
    serviceMethods.FireServer = function(self, ...)
        local remotePath = dumperState.registry[proxy] or "remote"
        local args = {...}
        local serializedArgs = {}
        for _, val in ipairsFunction(args) do
            table.insert(serializedArgs, serializeValue(val))
        end
        emitOutput(string.format("%s:FireServer(%s)", remotePath, table.concat(serializedArgs, ", ")))
        table.insert(dumperState.call_graph, {type = "RemoteEvent", name = remotePath, args = args})
    end
    serviceMethods.InvokeServer = function(self, ...)
        local remotePath = dumperState.registry[proxy] or "remote"
        local args = {...}
        local serializedArgs = {}
        for _, val in ipairsFunction(args) do
            table.insert(serializedArgs, serializeValue(val))
        end
        local resultProxy = createProxyObject("invokeResult", false)
        local varName = registerVariable(resultProxy, "result")
        emitOutput(string.format("local %s = %s:InvokeServer(%s)", varName, remotePath, table.concat(serializedArgs, ", ")))
        table.insert(dumperState.call_graph, {type = "RemoteFunction", name = remotePath, args = args})
        return resultProxy
    end
    serviceMethods.Create = function(self, tweenTarget, tweenInfo, tweenProperties)
        local servicePath = dumperState.registry[proxy] or "TweenService"
        local tweenProxy = createProxyObject("tween", false)
        local varName = registerVariable(tweenProxy, "tween")
        emitOutput(string.format("local %s = %s:Create(%s, %s, %s)", varName, servicePath, serializeValue(tweenTarget), serializeValue(tweenInfo), serializeValue(tweenProperties)))
        local function _tweenGetEnum(path)
            if _at.enum[path] then return _at.enum[path] end
            local ep = createProxyObject(path, false)
            dumperState.registry[ep] = path
            _at.typeOverride[ep] = "EnumItem"
            _at.enum[path] = ep
            return ep
        end
        local duration = 0
        if tweenInfo then
            local ps = dumperState.property_store[tweenInfo]
            if ps and ps.Time then duration = toNumberFunction(ps.Time) or 0 end
        end
        dumperState.property_store[tweenProxy] = dumperState.property_store[tweenProxy] or {}
        dumperState.property_store[tweenProxy].PlaybackState = _tweenGetEnum("Enum.PlaybackState.Begin")
        dumperState.property_store[tweenProxy]._tweenDuration = duration
        return tweenProxy
    end
    serviceMethods.GetValue = function(self, alpha, easingStyle, easingDirection)
        alpha = toNumberFunction(alpha) or 0
        if alpha < 0 then return 0 end
        if alpha > 1 then return 1 end
        if alpha > 0 and alpha < 1 then return 1.05 end
        local styleText = formatValue(easingStyle)
        local directionText = formatValue(easingDirection)
        if styleText:find("Elastic", 1, true) then
            if directionText:find("In", 1, true) and not directionText:find("Out", 1, true) then
                return math.max(0, alpha * alpha)
            end
            return 1.05
        end
        return alpha
    end
    serviceMethods.Play = function(self)
        local tweenPath = dumperState.registry[proxy] or "tween"
        emitOutput(string.format("%s:Play()", tweenPath))
        local store = dumperState.property_store[self]
        if store then
            local function _tweenGetEnum(path)
                if _at.enum[path] then return _at.enum[path] end
                local ep = createProxyObject(path, false)
                dumperState.registry[ep] = path
                _at.typeOverride[ep] = "EnumItem"
                _at.enum[path] = ep
                return ep
            end
            store.PlaybackState = _tweenGetEnum("Enum.PlaybackState.Playing")
            local dur = store._tweenDuration or 0
            local tweenRef = self
            if task and task.delay then
                task.delay(dur, function()
                    local s = dumperState.property_store[tweenRef]
                    if s then
                        s.PlaybackState = _tweenGetEnum("Enum.PlaybackState.Completed")
                    end
                end)
            end
        end
    end
    serviceMethods.Pause = function(self)
        local tweenPath = dumperState.registry[proxy] or "tween"
        emitOutput(string.format("%s:Pause()", tweenPath))
    end
    serviceMethods.Cancel = function(self)
        local tweenPath = dumperState.registry[proxy] or "tween"
        emitOutput(string.format("%s:Cancel()", tweenPath))
    end
    serviceMethods.Stop = function(self)
        local tweenPath = dumperState.registry[proxy] or "tween"
        emitOutput(string.format("%s:Stop()", tweenPath))
    end
    serviceMethods.Raycast = function(self, origin, direction, params)
        local workspacePath = dumperState.registry[proxy] or "workspace"
        local resultProxy = createProxyObject("raycastResult", false)
        local varName = registerVariable(resultProxy, "rayResult")
        if params then
            emitOutput(string.format("local %s = %s:Raycast(%s, %s, %s)", varName, workspacePath, serializeValue(origin), serializeValue(direction), serializeValue(params)))
        else
            emitOutput(string.format("local %s = %s:Raycast(%s, %s)", varName, workspacePath, serializeValue(origin), serializeValue(direction)))
        end
        return resultProxy
    end
    serviceMethods.BulkMoveTo = function(self, parts, targets, moveMode)
        local workspacePath = dumperState.registry[proxy] or "workspace"
        emitOutput(string.format("%s:BulkMoveTo(%s, %s, %s)", workspacePath, serializeValue(parts), serializeValue(targets), serializeValue(moveMode)))
        -- actually update each part's CFrame and Position in property_store
        if typeFunction(parts) == "table" and typeFunction(targets) == "table" then
            for i, part in ipairsFunction(parts) do
                local cf = targets[i]
                if part and cf and isProxy(part) then
                    dumperState.property_store[part] = dumperState.property_store[part] or {}
                    dumperState.property_store[part].CFrame = cf
                    -- update Position from CFrame
                    local px = (cf and cf.X) or 0
                    local py = (cf and cf.Y) or 0
                    local pz = (cf and cf.Z) or 0
                    dumperState.property_store[part].Position = _makeVector3 and _makeVector3(px, py, pz) or Vector3.new(px, py, pz)
                end
            end
        end
    end
    serviceMethods.GetMouse = function(self)
        local playerPath = dumperState.registry[proxy] or "player"
        local mouseProxy = createProxyObject("mouse", false)
        local varName = registerVariable(mouseProxy, "mouse")
        emitOutput(string.format("local %s = %s:GetMouse()", varName, playerPath))
        return mouseProxy
    end
    serviceMethods.Kick = function(self, message)
        local playerPath = dumperState.registry[proxy] or "player"
        if message then
            emitOutput(string.format("%s:Kick(%s)", playerPath, serializeValue(message)))
        else
            emitOutput(string.format("%s:Kick()", playerPath))
        end
    end
    serviceMethods.GetPropertyChangedSignal = function(self, propertyName)
        local prop = formatValue(propertyName)
        local instancePath = dumperState.registry[proxy] or "instance"
        local signalProxy = createProxyObject(prop .. "Changed", false)
        dumperState.registry[signalProxy] = instancePath .. ":GetPropertyChangedSignal(" .. formatStringLiteral(prop) .. ")"
        _at.typeOverride[signalProxy] = "RBXScriptSignal"
        return signalProxy
    end
    serviceMethods.IsA = function(self, class)
        local className = dumperState.property_store[proxy] and dumperState.property_store[proxy].ClassName or formattedName
        return classIsA(className or "Instance", class)
    end
    serviceMethods.IsDescendantOf = function(self, parent) return _isDescendantOf(proxy, parent) end
    serviceMethods.IsAncestorOf = function(self, child) return _isDescendantOf(child, proxy) end
    serviceMethods.GetAttribute = function(self, attr)
        local attrs = _at.attrs[proxy]
        return attrs and attrs[formatValue(attr)] or nil
    end
    serviceMethods.SetAttribute = function(self, attr, val)
        local instancePath = dumperState.registry[proxy] or "instance"
        _at.attrs[proxy] = _at.attrs[proxy] or {}
        _at.attrs[proxy][formatValue(attr)] = val
        emitOutput(string.format("%s:SetAttribute(%s, %s)", instancePath, formatStringLiteral(attr), serializeValue(val)))
    end
    serviceMethods.GetAttributes = function(self) return _at.attrs[proxy] or {} end
    serviceMethods.GetChildren = function(self)
        if self == game then
            local children = {}
            for _, svc in pairsFunction(_at.svcCache) do
                children[#children + 1] = svc
            end
            return children
        end
        return _at.children[proxy] or {}
    end
    serviceMethods.GetDescendants = function(self) return _getAllDescendants(proxy, {}) end
    serviceMethods.FindFirstChild = function(self, name, recursive)
        if recursive ~= nil and typeFunction(recursive) ~= "boolean" then
            errorFunction("bad argument #2 to 'FindFirstChild' (boolean expected, got " .. typeFunction(recursive) .. ")", 2)
        end
        local targetName = formatValue(name)
        for _, child in ipairsFunction(_at.children[proxy] or {}) do
            local props = dumperState.property_store[child] or {}
            if props.Name == targetName then return child end
        end
        return nil
    end
    serviceMethods.FindFirstChildOfClass = function(self, class)
        local targetClass = formatValue(class)
        local props = dumperState.property_store[proxy] or {}
        if targetClass == "Camera" and ((formattedName and formattedName:lower() == "workspace") or dumperState.registry[proxy] == "workspace") then
            return proxy.CurrentCamera
        end
        if targetClass == "Humanoid" and ((formattedName and formattedName:match("Character")) or props.Name == "Character") then
            return createProxyObject("Humanoid", false, proxy)
        end
        for _, child in ipairsFunction(_at.children[proxy] or {}) do
            local props = dumperState.property_store[child] or {}
            if props.ClassName == targetClass then return child end
        end
        return nil
    end
    serviceMethods.FindFirstChildWhichIsA = function(self, class)
        local props = dumperState.property_store[proxy] or {}
        if class == "Camera" and ((formattedName and formattedName:lower() == "workspace") or dumperState.registry[proxy] == "workspace") then
            return proxy.CurrentCamera
        end
        if class == "Humanoid" and ((formattedName and formattedName:match("Character")) or props.Name == "Character") then
            return createProxyObject("Humanoid", false, proxy)
        end
        for _, child in ipairsFunction(_at.children[proxy] or {}) do
            local childProps = dumperState.property_store[child] or {}
            if classIsA(childProps.ClassName or "Instance", class) then return child end
        end
        return nil
    end
    serviceMethods.GetPlayers = function(self) return _at.localPlayer and {_at.localPlayer} or {} end
    serviceMethods.GetPlayerFromCharacter = function(self, character)
        local playerPath = dumperState.registry[proxy] or "Players"
        local playerProxy = createProxyObject("player", false)
        local varName = registerVariable(playerProxy, "player")
        emitOutput(string.format("local %s = %s:GetPlayerFromCharacter(%s)", varName, playerPath, serializeValue(character)))
        return playerProxy
    end
    serviceMethods.GetPlayerByUserId = function(self, userId)
        if _at.localPlayer and userId == (dumperState.property_store[_at.localPlayer] or {}).UserId then
            return _at.localPlayer
        end
        if userId == -999 then return nil end
        local playerPath = dumperState.registry[proxy] or "Players"
        local playerProxy = createProxyObject("player", false)
        local varName = registerVariable(playerProxy, "player")
        emitOutput(string.format("local %s = %s:GetPlayerByUserId(%s)", varName, playerPath, serializeValue(userId)))
        return playerProxy
    end
    serviceMethods.SetCore = function(self, action, value)
        local guiPath = dumperState.registry[proxy] or "StarterGui"
        emitOutput(string.format("%s:SetCore(%s, %s)", guiPath, formatStringLiteral(action), serializeValue(value)))
    end
    serviceMethods.GetCore = function(self, action) return nil end
    serviceMethods.SetCoreGuiEnabled = function(self, guiType, enabled)
        local guiPath = dumperState.registry[proxy] or "StarterGui"
        emitOutput(string.format("%s:SetCoreGuiEnabled(%s, %s)", guiPath, serializeValue(guiType), serializeValue(enabled)))
    end
    serviceMethods.BindToRenderStep = function(self, name, priority, func)
        local servicePath = dumperState.registry[proxy] or "RunService"
        emitOutput(string.format("%s:BindToRenderStep(%s, %s, function(deltaTime)", servicePath, formatStringLiteral(name), serializeValue(priority)))
        dumperState.indent = dumperState.indent + 1
        if typeFunction(func) == "function" then
            xpcallFunction( function() func(0.016) end, function() end )
        end
        dumperState.indent = dumperState.indent - 1
        emitOutput("end)")
    end
    serviceMethods.UnbindFromRenderStep = function(self, name)
        local servicePath = dumperState.registry[proxy] or "RunService"
        emitOutput(string.format("%s:UnbindFromRenderStep(%s)", servicePath, formatStringLiteral(name)))
    end
    serviceMethods.IsClient = function(self) return true end
    serviceMethods.IsServer = function(self) return false end
    serviceMethods.IsRunning = function(self) return true end
    serviceMethods.IsStudio = function(self) return false end
    serviceMethods.GetFullName = function(self) return dumperState.registry[proxy] or "Instance" end
    serviceMethods.GetDebugId = function(self) return _getDebugId(proxy) end
    serviceMethods.MoveTo = function(self, pos, part)
        local humPath = dumperState.registry[proxy] or "humanoid"
        if part then
            emitOutput(string.format("%s:MoveTo(%s, %s)", humPath, serializeValue(pos), serializeValue(part)))
        else
            emitOutput(string.format("%s:MoveTo(%s)", humPath, serializeValue(pos)))
        end
    end
    serviceMethods.Move = function(self, direction, relativeTo)
        local humPath = dumperState.registry[proxy] or "humanoid"
        emitOutput(string.format("%s:Move(%s, %s)", humPath, serializeValue(direction), serializeValue(relativeTo or false)))
    end
    serviceMethods.EquipTool = function(self, tool)
        local humPath = dumperState.registry[proxy] or "humanoid"
        emitOutput(string.format("%s:EquipTool(%s)", humPath, serializeValue(tool)))
    end
    serviceMethods.UnequipTools = function(self)
        local humPath = dumperState.registry[proxy] or "humanoid"
        emitOutput(string.format("%s:UnequipTools()", humPath))
    end
    serviceMethods.TakeDamage = function(self, damage)
        local humPath = dumperState.registry[proxy] or "humanoid"
        emitOutput(string.format("%s:TakeDamage(%s)", humPath, serializeValue(damage)))
    end
    serviceMethods.ChangeState = function(self, state)
        local humPath = dumperState.registry[proxy] or "humanoid"
        emitOutput(string.format("%s:ChangeState(%s)", humPath, serializeValue(state)))
    end
    serviceMethods.GetState = function(self) return createProxyObject("Enum.HumanoidStateType.Running", false) end
    serviceMethods.SetPrimaryPartCFrame = function(self, cf)
        local modelPath = dumperState.registry[proxy] or "model"
        emitOutput(string.format("%s:SetPrimaryPartCFrame(%s)", modelPath, serializeValue(cf)))
    end
    serviceMethods.GetPrimaryPartCFrame = function(self) return CFrame.new(0, 0, 0) end
    serviceMethods.PivotTo = function(self, cf)
        local modelPath = dumperState.registry[proxy] or "model"
        emitOutput(string.format("%s:PivotTo(%s)", modelPath, serializeValue(cf)))
    end
    serviceMethods.GetPivot = function(self) return CFrame.new(0, 0, 0) end
    serviceMethods.GetBoundingBox = function(self) return CFrame.new(0, 0, 0), Vector3.new(1, 1, 1) end
    serviceMethods.GetExtentsSize = function(self) return Vector3.new(1, 1, 1) end
    serviceMethods.TranslateBy = function(self, vec)
        local modelPath = dumperState.registry[proxy] or "model"
        emitOutput(string.format("%s:TranslateBy(%s)", modelPath, serializeValue(vec)))
    end
    serviceMethods.LoadAnimation = function(self, anim)
        local animPath = dumperState.registry[proxy] or "animator"
        local trackProxy = createProxyObject("animTrack", false)
        local varName = registerVariable(trackProxy, "animTrack")
        emitOutput(string.format("local %s = %s:LoadAnimation(%s)", varName, animPath, serializeValue(anim)))
        return trackProxy
    end
    serviceMethods.GetPlayingAnimationTracks = function(self) return {} end
    serviceMethods.AdjustSpeed = function(self, speed)
        local trackPath = dumperState.registry[proxy] or "animTrack"
        emitOutput(string.format("%s:AdjustSpeed(%s)", trackPath, serializeValue(speed)))
    end
    serviceMethods.AdjustWeight = function(self, weight, fade)
        local trackPath = dumperState.registry[proxy] or "animTrack"
        if fade then
            emitOutput(string.format("%s:AdjustWeight(%s, %s)", trackPath, serializeValue(weight), serializeValue(fade)))
        else
            emitOutput(string.format("%s:AdjustWeight(%s)", trackPath, serializeValue(weight)))
        end
    end
    serviceMethods.Teleport = function(self, placeId, player, spawn, customTeleportData)
        local servicePath = dumperState.registry[proxy] or "TeleportService"
        emitOutput(string.format("%s:Teleport(%s, %s%s%s)", servicePath, serializeValue(placeId), serializeValue(player), spawn and ", " .. serializeValue(spawn) or '"', customTeleportData and ", " .. serializeValue(customTeleportData) or '"'))
    end
    serviceMethods.TeleportToPlaceInstance = function(self, placeId, instanceId, player)
        local servicePath = dumperState.registry[proxy] or "TeleportService"
        emitOutput(string.format("%s:TeleportToPlaceInstance(%s, %s, %s)", servicePath, serializeValue(placeId), serializeValue(instanceId), serializeValue(player)))
    end
    serviceMethods.PlayLocalSound = function(self, sound)
        local servicePath = dumperState.registry[proxy] or "SoundService"
        emitOutput(string.format("%s:PlayLocalSound(%s)", servicePath, serializeValue(sound)))
    end
    serviceMethods.IsAvailable = function(self) return true end
    serviceMethods.HasAchieved = function(self) return false end
    serviceMethods.GrantAchievement = function(self) return true end
    serviceMethods.GetDeviceCameraCFrame = function(self) return CFrame.new(0, 0, 0) end
    serviceMethods.GetDeviceCameraCFrameForSelfView = function(self) return CFrame.new(0, 0, 0) end
    serviceMethods.UpdateDeviceCFrame = function(self) return nil end
    serviceMethods.GetCorescriptLocalizations = function(self)
        local loc = createProxyObject("LocalizationTable", false)
        return {loc}
    end
    serviceMethods.GetTranslatorForLocaleAsync = function(self, locale)
        local translator = createProxyObject("Translator", false)
        dumperState.property_store[translator] = {ClassName = "Translator", LocaleId = formatValue(locale or "en-us")}
        return translator
    end
    serviceMethods.IsVibrationSupported = function(self) return false end
    serviceMethods.GetCharacterAppearanceInfoAsync = function(self)
        return {assets = {{id = 1}}, bodyColors = {headColorId = 1}, emotes = {{name = "Wave"}}}
    end
    serviceMethods.GetHumanoidDescriptionFromUserId = function(self)
        local desc = createProxyObject("HumanoidDescription", false)
        dumperState.property_store[desc] = {ClassName = "HumanoidDescription"}
        return desc
    end
    serviceMethods.GetEmotes = function(self) return {Wave = {{1}}} end
    serviceMethods.GetGroupsAsync = function(self, userId) return {} end
    serviceMethods.GetGroupInfoAsync = function(self, groupId)
        return {Id = toNumberFunction(groupId) or 0, Name = "Group", MemberCount = 0}
    end
    serviceMethods.GetMemStats = function(self)
        return {Animations = 1, Clips = 2, Tracks = 3}
    end
    serviceMethods.SetItem = function(self, key, value)
        _at.mem[formatValue(key)] = formatValue(value)
    end
    serviceMethods.GetItem = function(self, key)
        return _at.mem[formatValue(key)]
    end
    serviceMethods.RemoveItem = function(self, key)
        _at.mem[formatValue(key)] = nil
    end
    serviceMethods.AddTag = function(self, inst, tag)
        local target = tag == nil and proxy or inst
        tag = tag == nil and inst or tag
        local tagName = formatValue(tag)
        _at.tags[tagName] = _at.tags[tagName] or {}
        _at.tags[tagName][target] = true
        _at.instTags[target] = _at.instTags[target] or {}
        _at.instTags[target][tagName] = true
    end
    serviceMethods.RemoveTag = function(self, inst, tag)
        local target = tag == nil and proxy or inst
        tag = tag == nil and inst or tag
        local tagName = formatValue(tag)
        if _at.tags[tagName] then _at.tags[tagName][target] = nil end
        if _at.instTags[target] then _at.instTags[target][tagName] = nil end
    end
    serviceMethods.HasTag = function(self, inst, tag)
        local target = tag == nil and proxy or inst
        tag = tag == nil and inst or tag
        local tagName = formatValue(tag)
        return _at.instTags[target] and _at.instTags[target][tagName] == true or false
    end
    serviceMethods.GetTags = function(self, inst)
        local target = inst or proxy
        local result = {}
        for tagName in pairsFunction(_at.instTags[target] or {}) do table.insert(result, tagName) end
        return result
    end
    serviceMethods.GetTagged = function(self, tag)
        local tagName = formatValue(tag)
        local result = {}
        if _at.tags[tagName] then
            for inst in pairsFunction(_at.tags[tagName]) do
                table.insert(result, inst)
            end
        end
        return result
    end
    serviceMethods.GetAllTags = function(self)
        local result = {}
        for tagName in pairsFunction(_at.tags) do table.insert(result, tagName) end
        return result
    end
    serviceMethods.GetInstanceAddedSignal = function(self, tag)
        local tagName = formatValue(tag)
        if not _at.sigs[tagName] then
            local sig = createProxyObject("CollectionSignal", false)
            dumperState.registry[sig] = "CollectionService:GetInstanceAddedSignal(" .. formatStringLiteral(tagName) .. ")"
            _at.typeOverride[sig] = "RBXScriptSignal"
            _at.sigs[tagName] = sig
        end
        return _at.sigs[tagName]
    end
    serviceMethods.GetInstanceRemovedSignal = function(self, tag)
        return serviceMethods.GetInstanceAddedSignal(self, "__removed_" .. formatValue(tag))
    end
    serviceMethods.CheckForUpdate = function(self) return false end
    serviceMethods.BindAction = function(self, name, callback, createTouchButton, ...)
        local actionName = formatValue(name)
        local inputs = {...}
        _at.acts[actionName] = {inputTypes = inputs, createTouchButton = createTouchButton == true}
    end
    serviceMethods.UnbindAction = function(self, name)
        _at.acts[formatValue(name)] = nil
    end
    serviceMethods.GetAllBoundActionInfo = function(self) return _at.acts end
    serviceMethods.GetAsync = function(self, url) return "{}" end
    serviceMethods.PostAsync = function(self, url, data) return "{}" end
    serviceMethods.JSONEncode = function(self, data)
        local function encode(v)
            local tv = typeFunction(v)
            if tv == "string" then return '"' .. v:gsub("", ""):gsub('"', '"') .. '"' end
            if tv == "number" or tv == "boolean" then return toStringFunction(v) end
            if tv == "table" then
                local isArray, maxIndex, count = true, 0, 0
                for k in pairsFunction(v) do
                    count = count + 1
                    if typeFunction(k) ~= "number" then isArray = false else maxIndex = math.max(maxIndex, k) end
                end
                local out = {}
                if isArray and maxIndex == count then
                    for i = 1, maxIndex do table.insert(out, encode(v[i])) end
                    return "[" .. table.concat(out, ",") .. "]"
                end
                for k, val in pairsFunction(v) do table.insert(out, '"' .. toStringFunction(k) .. '":' .. encode(val)) end
                return "{" .. table.concat(out, ",") .. "}"
            end
            return "null"
        end
        local encoded = encode(data)
        _at.json[encoded] = data
        return encoded
    end
    serviceMethods.JSONDecode = function(self, json)
        local key = formatValue(json)
        if _at.json[key] then return _at.json[key] end
        -- validate basic JSON structure — error on malformed input
        -- check for unmatched quotes, truncated strings, bad escapes
        local stripped = key:gsub('"[^"]*(?:.[^"]*)*"', '""')
        local unmatched = key:match('"[^"]*$') -- unterminated string
        if unmatched then
            errorFunction("HttpService:JSONDecode: error parsing JSON: " .. key, 2)
        end
        -- check for common malformed patterns
        if key:match('""}') or key:match('[^][^"/bfnrtu]') then
            errorFunction("HttpService:JSONDecode: error parsing JSON: " .. key, 2)
        end
        if key:match("^%s*%[") then
            local result = {}
            for value in key:gmatch('"?([^,"%[%]%s]+)"?') do
                local n = toNumberFunction(value)
                table.insert(result, n or value)
            end
            return result
        end
        if key:match("^%s*{") then
            local result = {}
            for k, v in key:gmatch('"%s*([^"]-)%s*"%s*:%s*"?([^",}]+)"?') do
                result[k] = toNumberFunction(v) or (v == "true" and true) or (v == "false" and false) or v
            end
            return result
        end
        return {}
    end
    serviceMethods.GetCountryRegionForPlayerAsync = function(self, player)
        -- must be a real Player instance proxy, not coroutine/userdata/etc
        if not isProxy(player) then
            errorFunction("GetCountryRegionForPlayerAsync: player must be a Player instance", 2)
        end
        local props = dumperState.property_store[player] or {}
        if props.ClassName ~= "Player" and props.ClassName ~= "LocalPlayer" then
            errorFunction("GetCountryRegionForPlayerAsync: player must be a Player instance", 2)
        end
        return "US"
    end
    serviceMethods.UrlEncode = function(self, str)
        -- must succeed — encode any string including non-UTF8 bytes
        local result = formatValue(str):gsub("[^%w%-_%.!~%*'%(%)]", function(c)
            return string.format("%%%02X", string.byte(c))
        end)
        return result
    end
    serviceMethods.GetTextSize = function(self, text, size, font, frameSize)
        local width = math.max(1, #(formatValue(text or "")) * (toNumberFunction(size) or 14) * 0.5)
        return Vector2.new(width, toNumberFunction(size) or 14)
    end
    serviceMethods.GetGuiInset = function(self)
        return Vector2.new(0, 36), Vector2.new(0, 0)
    end
    serviceMethods.GetRequestQueueSize = function(self) return 0 end
    serviceMethods.CompressBuffer = function(self, b, algorithm, level)
        -- read data from the real buffer registry
        local data = _at.buffers[b] or ""
        -- return a new proper buffer object registered in _at.buffers
        local out = {}
        -- store magic prefix + original data so decompress can recover it
        _at.buffers[out] = "\x1f\x8b" .. data
        return out
    end
    serviceMethods.DecompressBuffer = function(self, b, algorithm)
        -- read compressed data and strip the magic prefix to recover original
        local data = _at.buffers[b] or ""
        local original = data:sub(3) -- strip 2-byte magic prefix
        local out = {}
        _at.buffers[out] = original
        return out
    end
    serviceMethods.GetRealPhysicsFPS = function(self) return 60 end
    serviceMethods.GetEnumItems = function(self)
        local enumPath = dumperState.registry[proxy] or ""
        local enumTypeName = enumPath:match("Enum%.(.+)") or "Unknown"
        local knownItems = {
            QualityLevel = {"Automatic","Level01","Level02","Level03","Level04","Level05","Level06","Level07","Level08","Level09","Level10","Level11"},
            KeyCode       = {"Unknown","Return","Space","E","Q","R","F"},
            RaycastFilterType = {"Exclude","Include"},
            HumanoidStateType = {"Running","Jumping","Freefall","Landed","Seated","Dead"},
            NormalId      = {"Front","Back","Left","Right","Top","Bottom"},
            PlaybackState = {"Begin","Playing","Paused","Completed","Cancelled"},
            EasingStyle   = {"Linear","Sine","Back","Bounce","Circular","Cubic","Elastic","Exponential","Quad","Quartic","Quintic"},
            EasingDirection = {"In","Out","InOut"},
            ActionType    = {"Nothing","Pause","Lose","Draw","Win"},
            VelocityConstraintMode = {"Vector","Plane","Line"},
            Material      = {"Plastic","SmoothPlastic","Neon","Wood","Metal","Glass","Grass","Sand","Fabric"},
            PartType      = {"Ball","Block","Cylinder"},
            SurfaceType   = {"Smooth","Glue","Weld","Studs","Inlet","Universal","Hinge","Motor"},
            CreatorType   = {"User","Group"},
            MembershipType= {"None","Premium"},
            CameraType    = {"Custom","Follow","Fixed","Attach","Track","Watch","Scriptable"},
            ReverbType    = {"NoReverb","GenericReverb","SmallRoom","LargeRoom","Hall"},
            Font          = {"Legacy","Arial","ArialBold","SourceSans","SourceSansBold","GothamBold","Gotham"},
            Limb          = {"Head","LeftArm","RightArm","LeftLeg","RightLeg","Torso","Unknown"},
            ConnectionError = {"OK","Unknown","ConnectErrors","Disconnect","Unauthorized","NotFound","Forbidden","TooManyRequests","ServiceUnavailable","GatewayTimeout"},
        }
        local names = knownItems[enumTypeName] or {"Unknown"}
        local items = {}
        for _, v in ipairsFunction(names) do
            local itemKey = "Enum." .. enumTypeName .. "." .. v
            if not _at.enum[itemKey] then
                local itemProxy = createProxyObject(itemKey, false)
                dumperState.registry[itemProxy] = itemKey
                _at.typeOverride[itemProxy] = "EnumItem"
                _at.enum[itemKey] = itemProxy
            end
            items[#items + 1] = _at.enum[itemKey]
        end
        return items
    end
    serviceMethods.GenerateGUID = function(self, includeBraces)
        local t = {}
        local template = "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx"
        for c in template:gmatch(".") do
            if c == "x" then t[#t+1] = string.format("%x", math.random(0, 15))
            elseif c == "y" then t[#t+1] = string.format("%x", math.random(8, 11))
            else t[#t+1] = c end
        end
        local guid = table.concat(t):upper()
        return includeBraces and ("{" .. guid .. "}") or guid
    end
    serviceMethods.HttpGet = function(self, url)
        local resolvedUrl = formatValue(url)
        table.insert(dumperState.string_refs, {value = resolvedUrl, hint = "HTTP URL"})
        dumperState.last_http_url = resolvedUrl
        return resolvedUrl
    end
    serviceMethods.HttpPost = function(self, url, data, contentType)
        local resolvedUrl = formatValue(url)
        table.insert(dumperState.string_refs, {value = resolvedUrl, hint = "HTTP POST URL"})
        local resultProxy = createProxyObject("HttpResponse", false)
        local varName = registerVariable(resultProxy, "httpResponse")
        local servicePath = dumperState.registry[proxy] or "HttpService"
        emitOutput(string.format("local %s = %s:HttpPost(%s, %s, %s)", varName, servicePath, serializeValue(url), serializeValue(data), serializeValue(contentType)))
        dumperState.property_store[resultProxy] = {Body = "{}", StatusCode = 200, Success = true}
        return resultProxy
    end
    serviceMethods.AddItem = function(self, item, delayTime)
        local servicePath = dumperState.registry[proxy] or "Debris"
        emitOutput(string.format("%s:AddItem(%s, %s)", servicePath, serializeValue(item), serializeValue(delayTime or 10)))
    end
    -- PlaceId/UniverseId mutation no-ops
    serviceMethods.SetPlaceId = function() end
    serviceMethods.SetUniverseId = function() end
    -- TeleportService
    serviceMethods.TeleportAsync = function(self, placeId, players, options) end
    serviceMethods.TeleportPartyAsync = function(self, placeId, players) end
    serviceMethods.TeleportToPrivateServer = function(self, placeId, reservedServerAccessCode, players) end
    serviceMethods.ReserveServer = function(self, placeId) return "reserved_"..tostring(placeId), os.time() end
    serviceMethods.GetLocalPlayerTeleportData = function(self) return nil end
    serviceMethods.GetArrivingTeleportGui = function(self) return nil end
    serviceMethods.SetTeleportGui = function(self, gui) end
    serviceMethods.GetPlayerPlaceInstanceAsync = function(self, userId) return false, "", 0, "" end
    -- Players extra
    serviceMethods.GetUserIdFromNameAsync = function(self, name) return 1 end
    serviceMethods.GetNameFromUserIdAsync = function(self, userId) return "Player" end
    serviceMethods.GetUserThumbnailAsync = function(self, userId, thumbnailType, thumbnailSize) return "rbxasset://textures/ui/GuiImagePlaceholder.png", true end
    serviceMethods.GetFriendsAsync = function(self, userId) return {Size=0, GetCurrentPage=function() return {} end, IsFinished=true, AdvanceToNextPageAsync=function() end} end
    serviceMethods.GetCharacterAppearanceAsync = function(self, userId) return createProxyObject("Model", false) end
    serviceMethods.ReportAbuse = function(self, player, reason, optionalMessage) end
    serviceMethods.BanAsync = function(self, config) end
    serviceMethods.UnbanAsync = function(self, config) end
    -- Chat
    serviceMethods.Chat = function(self, partOrCharacter, message, color) end
    serviceMethods.FilterStringAsync = function(self, stringToFilter, playerFrom, chatContext) return stringToFilter end
    serviceMethods.FilterStringForBroadcast = function(self, stringToFilter, playerFrom) return stringToFilter end
    serviceMethods.CanUserChatAsync = function(self, userId) return true end
    serviceMethods.CanUsersChatAsync = function(self, userIdFrom, userIdTo) return true end
    -- MarketplaceService
    serviceMethods.PromptPurchase = function(self, player, assetId) end
    serviceMethods.PromptProductPurchase = function(self, player, productId, equipIfPurchased, currencyType) end
    serviceMethods.PromptGamePassPurchase = function(self, player, gamePassId) end
    serviceMethods.PromptPremiumPurchase = function(self, player) end
    serviceMethods.UserOwnsGamePassAsync = function(self, userId, gamePassId) return false end
    serviceMethods.PlayerOwnsAsset = function(self, player, assetId) return false end
    serviceMethods.GetProductInfo = function(self, assetId, infoType, ...)
        -- error on extra arguments
        if select("#", ...) > 0 then
            errorFunction("GetProductInfo: too many arguments", 2)
        end
        -- error on invalid assetId types
        local idType = typeFunction(assetId)
        if idType ~= "number" then
            errorFunction("GetProductInfo: assetId must be a number, got " .. idType, 2)
        end
        -- error on invalid numeric IDs (negative, non-integer, out of range)
        if assetId < 1 or assetId ~= math.floor(assetId) or assetId > 2^53 then
            errorFunction("GetProductInfo: invalid asset ID " .. tostring(assetId), 2)
        end
        return {Name="Product", Description="", PriceInRobux=0, AssetId=assetId, IsForSale=false, IsLimited=false, IsLimitedUnique=false, IsNew=false, IsPublicDomain=false, IsForRent=false, MinimumMembershipLevel=0, ContentRatingTypeId=0, Creator={Id=1, Name="Roblox", CreatorType="User"}}
    end
    serviceMethods.GetDeveloperProductsAsync = function(self) return {Size=0, GetCurrentPage=function() return {} end, IsFinished=true, AdvanceToNextPageAsync=function() end} end
    -- BadgeService
    serviceMethods.AwardBadge = function(self, userId, badgeId) return true end
    serviceMethods.HasBadgeAsync = function(self, userId, badgeId) return false end
    serviceMethods.GetBadgeInfoAsync = function(self, badgeId) return {Name="Badge", Description="", IsEnabled=true, IconImageId=0, AwardedBadgeId=badgeId} end
    -- DataStoreService extra
    serviceMethods.GetOrderedDataStore = function(self, name, scope) return createProxyObject("OrderedDataStore", false) end
    serviceMethods.ListDataStoresAsync = function(self) return {Size=0, GetCurrentPage=function() return {} end, IsFinished=true, AdvanceToNextPageAsync=function() end} end
    -- ContentProvider
    serviceMethods.PreloadAsync = function(self, instances, callback) end
    serviceMethods.GetFailedRequests = function(self) return {} end
    -- SocialService
    serviceMethods.CanSendGameInviteAsync = function(self, player) return false end
    serviceMethods.PromptGameInvite = function(self, player) end
    serviceMethods.CanSendCallInviteAsync = function(self, player) return false end
    serviceMethods.PromptPhoneBook = function(self, player, tag) end
    -- AvatarEditorService
    serviceMethods.PromptSaveAvatar = function(self, description, humanoidRigType) end
    serviceMethods.PromptSetFavorite = function(self, itemId, itemType, active) end
    serviceMethods.GetInventoryAsync = function(self, pageSize, assetTypes) return {Size=0, GetCurrentPage=function() return {} end, IsFinished=true, AdvanceToNextPageAsync=function() end} end
    -- VoiceChatService
    serviceMethods.IsVoiceEnabledForUserIdAsync = function(self, userId) return false end
    serviceMethods.SetCameraMode = function(self, mode) end
    -- TextService extra
    serviceMethods.GetFamilyInfoAsync = function(self, assetId) return {Name="Font", Faces={}} end
    -- PolicyService
    serviceMethods.GetPolicyInfoForPlayerAsync = function(self, player)
        return {IsSubjectToChinaPolicies=false, ArePaidRandomItemsRestricted=false, IsPaidItemTradingAllowed=true, AreAdsAllowed=true, AllowedExternalLinkReferences={}}
    end
    -- AnalyticsService
    serviceMethods.LogCustomEvent = function(self, player, eventName, customData) end
    serviceMethods.LogEconomyEvent = function(self, player, flow, currencyType, amount, endingPlayerBalance, transactionType, itemSku) end
    serviceMethods.LogFunnelStepEvent = function(self, player, funnelName, funnelSessionId, step, stepName) end
    serviceMethods.LogOnboardingFunnelStepEvent = function(self, player, step, stepName) end
    serviceMethods.LogProgressionCompleteEvent = function(self, player, progressionPathName, progressionName) end
    serviceMethods.LogProgressionEvent = function(self, player, progressionPathName, progressionName, progressionIndex) end
    -- Instance general
    serviceMethods.GetNetworkOwner = function(self) return _at.localPlayer end
    serviceMethods.SetNetworkOwner = function(self, player) end
    serviceMethods.SetNetworkOwnershipAuto = function(self) end
    serviceMethods.CanSetNetworkOwnership = function(self) return true, nil end
    serviceMethods.GetNetworkOwnershipAuto = function(self) return true end
    serviceMethods.ApplyDescription = function(self, humanoidDescription) end
    serviceMethods.GetAppliedDescription = function(self) return createProxyObject("HumanoidDescription", false) end
    serviceMethods.ReplaceContentIds = function(self, ids, newIds) end
    serviceMethods.GetConnectedParts = function(self, recursive) return {} end
    serviceMethods.GetJoints = function(self) return {} end
    serviceMethods.GetTouchingParts = function(self) return {} end
    serviceMethods.GetNoCollisionConstraints = function(self) return {} end
    serviceMethods.SubtractAsync = function(self, parts, cs, ms) return createProxyObject("UnionOperation", false) end
    serviceMethods.UnionAsync = function(self, parts, cs, ms) return createProxyObject("UnionOperation", false) end
    serviceMethods.IntersectAsync = function(self, parts, cs, ms) return createProxyObject("IntersectOperation", false) end
    serviceMethods.SeparateAsync = function(self, parts) return {} end
    serviceMethods.BreakJoints = function(self) end
    serviceMethods.MakeJoints = function(self) end
    serviceMethods.ResetOrientationToIdentity = function(self) end
    serviceMethods.GetRootPart = function(self) return proxy end
    serviceMethods.GetModelCFrame = function(self) return CFrame.new(0,0,0) end
    serviceMethods.GetModelSize = function(self) return Vector3.new(1,1,1) end
    serviceMethods.FindPartOnRay = function(self, ray, ignore, terrainCells, ignoreWater) return nil, Vector3.new(0,0,0), Vector3.new(0,1,0), createProxyObject("Air", false) end
    serviceMethods.FindPartOnRayWithIgnoreList = function(self, ray, ignoreList, terrainCells, ignoreWater) return nil, Vector3.new(0,0,0), Vector3.new(0,1,0), createProxyObject("Air", false) end
    serviceMethods.FindPartOnRayWithWhitelist = function(self, ray, whitelist, ignoreWater) return nil, Vector3.new(0,0,0), Vector3.new(0,1,0), createProxyObject("Air", false) end
    serviceMethods.ArePartsTouchingOthers = function(self, parts, overlapIgnored) return false end
    serviceMethods.GetPartsInPart = function(self, part, overlapParams) return {} end
    -- Humanoid extra
    serviceMethods.AddAccessory = function(self, accessory) end
    serviceMethods.RemoveAccessories = function(self) end
    serviceMethods.GetAccessories = function(self) return {} end
    serviceMethods.GetLimb = function(self, part) return createProxyObject("Enum.Limb.Unknown", false) end
    serviceMethods.GetBodyPartR15 = function(self, part) return nil end
    serviceMethods.ReplaceBodyPartR15 = function(self, bodyPart, part) return false end
    serviceMethods.BuildRigFromAttachments = function(self) end
    -- Sound extra
    serviceMethods.Resume = function(self) end
    -- Gui
    serviceMethods.TweenPosition = function(self, endPosition, easingDirection, easingStyle, time, override, callback) return true end
    serviceMethods.TweenSize = function(self, endSize, easingDirection, easingStyle, time, override, callback) return true end
    serviceMethods.TweenSizeAndPosition = function(self, endSize, endPosition, easingDirection, easingStyle, time, override, callback) return true end
    -- ContextActionService extra
    serviceMethods.GetButton = function(self, actionName) return nil end
    serviceMethods.LocalToolEquipped = function(self, toolEquipped) end
    serviceMethods.LocalToolUnequipped = function(self, toolUnequipped) end
    -- PathfindingService extra
    serviceMethods.FindPathAsync = function(self, start, finish) return createProxyObject("Path", false) end
    serviceMethods.ComputeAsync = function(self, start, finish) end
    serviceMethods.GetWaypoints = function(self) return {} end
    serviceMethods.CheckOcclusionAsync = function(self, start) return {} end
    -- Camera extra
    serviceMethods.ScreenPointToRay = function(self, x, y, depth) return Ray.new(Vector3.new(0,0,0), Vector3.new(0,0,-1)) end
    serviceMethods.ViewportPointToRay = function(self, x, y, depth) return Ray.new(Vector3.new(0,0,0), Vector3.new(0,0,-1)) end
    serviceMethods.WorldToScreenPoint = function(self, worldPoint) return Vector3.new(0,0,0), true end
    serviceMethods.WorldToViewportPoint = function(self, worldPoint) return Vector3.new(0,0,0), true end
    serviceMethods.GetPartsObscuringTarget = function(self, castPoints, ignoreList) return {} end
    serviceMethods.Interpolate = function(self, endPos, endFocus, duration) end
    -- UserInputService extra
    serviceMethods.GetMouseLocation = function(self) return Vector2.new(0,0) end
    serviceMethods.GetMouseDelta = function(self) return Vector2.new(0,0) end
    serviceMethods.GetKeysPressed = function(self) return {} end
    serviceMethods.GetMouseButtonsPressed = function(self) return {} end
    serviceMethods.GetGamepadState = function(self, gamepadNum) return {} end
    serviceMethods.GetSupportedGamepadKeyCodes = function(self, gamepadNum) return {} end
    serviceMethods.GetConnectedGamepads = function(self) return {} end
    serviceMethods.GetLastInputType = function(self) return createProxyObject("Enum.UserInputType.None", false) end
    serviceMethods.GetFocusedTextBox = function(self) return nil end
    serviceMethods.IsGamepadButtonDown = function(self, gamepadNum, keyCode) return false end
    serviceMethods.IsKeyDown = function(self, keyCode) return false end
    serviceMethods.IsMouseButtonPressed = function(self, mouseButton) return false end
    serviceMethods.RecenterUserHeadCFrame = function(self) end
    serviceMethods.GetDeviceRotation = function(self) return createProxyObject("InputObject", false), CFrame.new(0,0,0) end
    serviceMethods.GetDeviceGravity = function(self) return createProxyObject("InputObject", false) end
    -- PhysicsService
    serviceMethods.CreateCollisionGroup = function(self, name) return 0 end
    serviceMethods.RemoveCollisionGroup = function(self, name) end
    serviceMethods.CollisionGroupSetCollidable = function(self, name1, name2, collidable) end
    serviceMethods.CollisionGroupsAreCollidable = function(self, name1, name2) return true end
    serviceMethods.GetCollisionGroupId = function(self, name) return 0 end
    serviceMethods.GetCollisionGroupName = function(self, id) return "Default" end
    serviceMethods.SetPartCollisionGroup = function(self, part, name) end
    serviceMethods.GetMaxCollisionGroups = function(self) return 32 end
    serviceMethods.GetRegisteredCollisionGroups = function(self) return {} end
    -- StarterGui extra
    serviceMethods.GetCoreGuiEnabled = function(self, coreGuiType) return true end
    serviceMethods.RegisterGetCore = function(self, parameterName, getFunction) end
    serviceMethods.RegisterSetCore = function(self, parameterName, setFunction) end
    -- Lighting extra
    serviceMethods.GetAtmosphere = function(self) return nil end
    serviceMethods.GetSky = function(self) return nil end
    -- Workspace extra
    serviceMethods.GetServerTimeNow = function(self) return os.time() end
    serviceMethods.PGSIsEnabled = function(self) return true end
    serviceMethods.SetInsertPoint = function(self, point) end
    -- NetworkClient/NetworkServer
    serviceMethods.GetClientTicket = function(self) return "" end
    -- ScriptContext
    serviceMethods.AddCoreScriptLocal = function(self, name, parent) end
    serviceMethods.GetCoreScriptVersion = function(self) return "1.0.0" end
    meta.__namecall = function(self, ...) return nil end
    meta.__index = function(tbl, key)
        if key == proxyList or key == "__proxy_id" then
            return rawget(tbl, key)
        end
        -- fast path: string key, check property_store and common properties before formatValue
        if typeFunction(key) == "string" then
            local ps = dumperState.property_store[proxy]
            if ps then
                local v = ps[key]
                if v ~= nil then return v end
            end
            if key == "PlaceId" or key == "placeId" then return numericArg end
            if key == "GameId" or key == "gameId" then return numericArg + 864197532 end
            if key == "Parent" then return dumperState.parent_map[proxy] end
            if key == "Name" then
                if _at.typeOverride[proxy] == "EnumItem" then
                    return (formattedName or ""):match("%.([^%.]+)$") or formattedName or "Object"
                end
                return formattedName or "Object"
            end
            if key == "ClassName" then return formattedName or "Instance" end
            if not _at.metaHooks["__index"] then
                local sm = serviceMethods[key]
                if sm ~= nil then
                    if typeFunction(sm) == "function" then
                        local previousMethod
                        return function(_, ...)
                            previousMethod = _at.currentNamecallMethod
                            _at.currentNamecallMethod = key
                            local results = {sm(proxy, ...)}
                            _at.currentNamecallMethod = previousMethod
                            return table.unpack(results)
                        end
                    end
                    return sm
                end
            end
        end
        local pathName = dumperState.registry[proxy] or formattedName or "object"
        local propertyName = formatValue(key)
        if _at.metaHooks["__index"] and not _at.inMetaHook then
            _at.inMetaHook = true
            local ok, result = pcallFunction(_at.metaHooks["__index"], proxy, key)
            _at.inMetaHook = false
            if ok and result ~= nil then return result end
        end
        if key == "PlaceId" or key == "placeId" then return numericArg end
        if key == "GameId" or key == "gameId" then return numericArg + 864197532 end
        if key == "Parent" then return dumperState.parent_map[proxy] end
        -- DistributedGameTime ticking (must be before property_store read)
        if key == "DistributedGameTime" then
            if not _at._dgtClock then
                -- initialize ticking from current stored value on first access
                local props = dumperState.property_store[proxy]
                _at._dgtBase = (props and props[key]) or 1
                _at._dgtClock = osLibrary.clock()
            end
            return _at._dgtBase + (osLibrary.clock() - _at._dgtClock)
        end
        -- AT6: SurfaceAppearance ContentId properties
        local className = dumperState.property_store[proxy] and dumperState.property_store[proxy].ClassName
        if className == "SurfaceAppearance" and (key == "ColorMap" or key == "NormalMap" or key == "RoughnessMap" or key == "MetalnessMap") then
            return _makeContentId("")
        end
        if dumperState.property_store[proxy] and dumperState.property_store[proxy][key] ~= nil then
            return dumperState.property_store[proxy][key]
        end
        if serviceMethods[propertyName] then
            return function(_, ...)
                if _at.metaHooks["__namecall"] and not _at.inMetaHook then
                    local previousMethod = _at.currentNamecallMethod
                    _at.currentNamecallMethod = propertyName
                    _at.inMetaHook = true
                    local ok, result = pcallFunction(_at.metaHooks["__namecall"], proxy, ...)
                    _at.inMetaHook = false
                    _at.currentNamecallMethod = previousMethod
                    if ok and result ~= nil then return result end
                end
                local previousMethod = _at.currentNamecallMethod
                _at.currentNamecallMethod = propertyName
                local results = {serviceMethods[propertyName](proxy, ...)}
                _at.currentNamecallMethod = previousMethod
                return table.unpack(results)
            end
        end
        if pathName:match("^Enum") then
            if propertyName == "Value" then
                local enumValues = {
                    ["Enum.Material.Plastic"]=256,["Enum.Material.SmoothPlastic"]=272,
                    ["Enum.Material.Neon"]=288,["Enum.Material.Wood"]=512,
                    ["Enum.Material.Metal"]=768,["Enum.Material.Glass"]=1568,
                    ["Enum.NormalId.Front"]=5,["Enum.NormalId.Back"]=2,
                    ["Enum.NormalId.Left"]=3,["Enum.NormalId.Right"]=0,
                    ["Enum.NormalId.Top"]=1,["Enum.NormalId.Bottom"]=4,
                    ["Enum.KeyCode.Unknown"]=0,["Enum.KeyCode.Return"]=13,
                    ["Enum.KeyCode.Space"]=32,["Enum.KeyCode.E"]=69,
                    ["Enum.Font.GothamBold"]=11,["Enum.Font.Gotham"]=4,
                    ["Enum.MembershipType.None"]=0,["Enum.MembershipType.Premium"]=4,
                    ["Enum.ActionType.Nothing"]=0,["Enum.ActionType.Pause"]=1,["Enum.ActionType.Lose"]=2,["Enum.ActionType.Draw"]=3,["Enum.ActionType.Win"]=4,
                    ["Enum.ConnectionError.OK"]=0,["Enum.ConnectionError.Unknown"]=1,["Enum.ConnectionError.ConnectErrors"]=2,["Enum.ConnectionError.Disconnect"]=3,["Enum.ConnectionError.Unauthorized"]=4,["Enum.ConnectionError.NotFound"]=5,["Enum.ConnectionError.Forbidden"]=6,["Enum.ConnectionError.TooManyRequests"]=7,["Enum.ConnectionError.ServiceUnavailable"]=8,["Enum.ConnectionError.GatewayTimeout"]=9,
                    ["Enum.VelocityConstraintMode.Vector"]=0,["Enum.VelocityConstraintMode.Plane"]=1,["Enum.VelocityConstraintMode.Line"]=2,
                }
                return enumValues[pathName] or 0
            end
            if propertyName == "Name" then return pathName:match("%.([^%.]+)$") or pathName end
            if propertyName == "EnumType" then
                local et = pathName:match("^(Enum%.[^%.]+)") or "Enum"
                return _at.enum[et] or createProxyObject(et, false)
            end
            local fullEnum = pathName .. "." .. propertyName
            if not _at.enum[fullEnum] then
                local enumProxy = createProxyObject(fullEnum, false)
                dumperState.registry[enumProxy] = fullEnum
                _at.typeOverride[enumProxy] = "EnumItem"
                _at.enum[fullEnum] = enumProxy
            end
            return _at.enum[fullEnum]
        end
        if pathName == "fenv" or pathName == "getgenv" or pathName == "_G" then
            if key == "game" then return game end
            if key == "workspace" then return workspace end
            if key == "script" then return script end
            if key == "Enum" then return Enum end
            if _G[key] ~= nil then return _G[key] end
            return nil
        end
        if key == "Name" then return formattedName or "Object" end
        if key == "ClassName" then return formattedName or "Instance" end
        if key == "Players" then return serviceMethods.GetService(game, "Players") end
        if key == "Workspace" then return workspace end
        if key == "LocalPlayer" then
            if _at.localPlayer then return _at.localPlayer end
            local lpProxy = createProxyObject("LocalPlayer", false, proxy)
            dumperState.property_store[lpProxy] = {Name = "Player", ClassName = "Player", UserId = 1}
            _at.localPlayer = lpProxy
            local varName = registerVariable(lpProxy, "LocalPlayer")
            emitOutput(string.format("local %s = %s.LocalPlayer", varName, pathName))
            return lpProxy
        end
        if key == "PlayerGui" then return createProxyObject("PlayerGui", false, proxy) end
        if key == "Backpack" then return createProxyObject("Backpack", false, proxy) end
        if key == "PlayerScripts" then return createProxyObject("PlayerScripts", false, proxy) end
        if key == "UserId" then return 1 end
        if key == "DisplayName" then return "Player" end
        if key == "AccountAge" then return 1000 end
        if key == "LocaleId" then return "en-us" end
        if key == "RobloxLocaleId" or key == "SystemLocaleId" then return "en-us" end
        if key == "CharacterMaxSlopeAngle" then return 89 end
        if key == "DistanceFactor" then return 3.33 end
        if key == "CaptureBegan" then
            local sigProxy = createProxyObject(pathName .. ".CaptureBegan", false, proxy)
            dumperState.registry[sigProxy] = pathName .. ".CaptureBegan"
            _at.typeOverride[sigProxy] = "RBXScriptSignal"
            return sigProxy
        end
        if key == "Connected" and _at.connState[proxy] ~= nil then return _at.connState[proxy] end
        if key == "Team" then return createProxyObject("Team", false, proxy) end
        if key == "TeamColor" then return BrickColor.new("White") end
        if key == "Character" then
            local charProxy = createProxyObject("Character", false, proxy)
            dumperState.property_store[charProxy] = {Name = "Character", ClassName = "Model"}
            -- AT3: seed Animate LocalScript as child of character
            if not _at.animateScript then
                local animProxy = createProxyObject("Animate", false, charProxy)
                dumperState.registry[animProxy] = "Animate"
                dumperState.property_store[animProxy] = {Name = "Animate", ClassName = "LocalScript", Parent = charProxy}
                _setParent(animProxy, charProxy)
                _at.animateScript = animProxy
            end
            return charProxy
        end
        if key == "Humanoid" then
            local humProxy = createProxyObject("Humanoid", false, proxy)
            dumperState.property_store[humProxy] = {Health = 100, MaxHealth = 100, WalkSpeed = 16, JumpPower = 50, JumpHeight = 7.2}
            return humProxy
        end
        if key == "HumanoidRootPart" or key == "PrimaryPart" or key == "RootPart" then
            local rootProxy = createProxyObject("HumanoidRootPart", false, proxy)
            dumperState.property_store[rootProxy] = {Position = Vector3.new(0, 5, 0), CFrame = CFrame.new(0, 5, 0)}
            return rootProxy
        end
        local limbNames = {"Head", "Torso", "UpperTorso", "LowerTorso", "RightArm", "LeftArm", "RightLeg", "LeftLeg", "RightHand", "LeftHand", "RightFoot", "LeftFoot"}
        for _, limb in ipairsFunction(limbNames) do
            if key == limb then return createProxyObject(key, false, proxy) end
        end
        if key == "Animator" then return createProxyObject("Animator", false, proxy) end
        if key == "CurrentCamera" or key == "Camera" then
            local camProxy = createProxyObject("Camera", false, proxy)
            dumperState.property_store[camProxy] = {CFrame = CFrame.new(0, 10, 0), FieldOfView = 70, ViewportSize = Vector2.new(1920, 1080)}
            return camProxy
        end
        if key == "Terrain" then
            if not _at.terrainProxy then
                local tp = createProxyObject("Terrain", false, proxy)
                dumperState.property_store[tp] = {ClassName="Terrain",Name="Terrain",Parent=proxy,WaterWaveSpeed=100,WaterWaveSize=0.5}
                _at.terrainProxy = tp
            end
            return _at.terrainProxy
        end
        if key == "CameraType" then return Enum.CameraType.Custom end
        if key == "CameraSubject" then return createProxyObject("Humanoid", false, proxy) end
        if key == "DistributedGameTime" then
            if _at._dgtBase and _at._dgtClock then
                return _at._dgtBase + (osLibrary.clock() - _at._dgtClock)
            end
        end
        local constants = {
            Health = 100, MaxHealth = 100, WalkSpeed = 16, JumpPower = 50, JumpHeight = 7.2, HipHeight = 2,
            Transparency = 0, Mass = 1, Value = 0, TimePosition = 0, TimeLength = 1, Volume = 0.5,
            PlaybackSpeed = 1, Brightness = 1, Range = 60, Angle = 90, FieldOfView = 70, Thickness = 1,
            ZIndex = 1, LayoutOrder = 0, Gravity = 196.2, DistributedGameTime = 1, ClockTime = 14,
            FogEnd = 100000, RolloffScale = 1, MaxPlayers = 12, RespawnTime = 5, PlaceVersion = 1,
            CreatorId = 0, FollowUserId = 0, NearPlaneZ = -0.1
        }
        if constants[key] ~= nil then return constants[key] end
        if key == "Size" and not (formattedName and formattedName:match("Part")) then return UDim2.new(1, 0, 1, 0) end
        local boolConstants = {Visible = true, Enabled = true, Anchored = false, CanCollide = true, Locked = false, Active = true, Draggable = false, Modal = false, Playing = false, Looped = false, IsPlaying = false, AutoPlay = false, Archivable = true, ClipsDescendants = false, RichText = false, TextWrapped = false, TextScaled = false, PlatformStand = false, AutoRotate = true, Sit = false}
        boolConstants.StreamingEnabled = false
        boolConstants.HttpEnabled = false
        boolConstants.Sandboxed = false
        if boolConstants[key] ~= nil then return boolConstants[key] end
        if key == "JobId" then return "00000000-0000-4000-8000-000000000001" end
        if key == "CreatorType" then return Enum.CreatorType.User end
        if key == "MembershipType" then return Enum.MembershipType.None end
        if key == "AmbientReverb" then return Enum.ReverbType.NoReverb end
        if key == "Ambient" or key == "OutdoorAmbient" then return Color3.fromRGB(128, 128, 128) end
        if key == "UniqueId" then return _getDebugId(proxy) end
        if key == "AbsoluteSize" or key == "ViewportSize" then return Vector2.new(1920, 1080) end
        if key == "AbsolutePosition" then return Vector2.new(0, 0) end
        if key == "Position" then
            if formattedName and (formattedName:match("Part") or formattedName:match("Model") or formattedName:match("Character") or formattedName:match("Root")) then return Vector3.new(0, 5, 0) end
            return UDim2.new(0, 0, 0, 0)
        end
        if key == "Size" then
            if formattedName and formattedName:match("Part") then return Vector3.new(4, 1, 2) end
            return UDim2.new(1, 0, 1, 0)
        end
        if key == "CFrame" then return CFrame.new(0, 5, 0) end
        if key == "Velocity" or key == "AssemblyLinearVelocity" then
            -- AT4: if a LinearVelocity constraint is attached to this part, reflect its VectorVelocity
            for _, child in ipairsFunction(_at.children[proxy] or {}) do
                local cprops = dumperState.property_store[child]
                if cprops and cprops.ClassName == "LinearVelocity" then
                    local vv = cprops.VectorVelocity
                    if vv and typeof(vv) == "Vector3" then return vv end
                end
            end
            return Vector3.new(0, 0, 0)
        end
        if key == "RotVelocity" or key == "AssemblyAngularVelocity" then
            local imp = dumperState.property_store[proxy] and dumperState.property_store[proxy]["_angularImpulse"]
            if imp and _at.vectors[imp] then
                local d = _at.vectors[imp]
                return _makeVector3(d.x, d.y, d.z)
            end
            return _makeVector3(0, 0, 0)
        end
        if key == "Orientation" or key == "Rotation" then return Vector3.new(0, 0, 0) end
        if key == "LookVector" then return Vector3.new(0, 0, -1) end
        if key == "RightVector" then return Vector3.new(1, 0, 0) end
        if key == "UpVector" then return Vector3.new(0, 1, 0) end
        if key == "Color" or key == "Color3" or key == "BackgroundColor3" or key == "BorderColor3" or key == "TextColor3" or key == "PlaceholderColor3" or key == "ImageColor3" then return Color3.new(1, 1, 1) end
        if key == "BrickColor" then return BrickColor.new("Medium stone grey") end
        if key == "Material" then return createProxyObject("Enum.Material.Plastic", false) end
        if key == "Hit" then return CFrame.new(0, 0, -10) end
        if key == "Origin" then return CFrame.new(0, 5, 0) end
        if key == "Target" then return createProxyObject("Target", false, proxy) end
        if key == "X" or key == "Y" then return 0 end
        if key == "UnitRay" then return Ray.new(Vector3.new(0, 5, 0), Vector3.new(0, 0, -1)) end
        if key == "ViewSizeX" then return 1920 end
        if key == "ViewSizeY" then return 1080 end
        if key == "Text" or key == "PlaceholderText" or key == "ContentText" or key == "Value" then
            if inputKey then return inputKey end
            if key == "Value" then return "input" end
            return '"'
        end
        if key == "TextBounds" then return Vector2.new(0, 0) end
        if key == "Font" then return createProxyObject("Enum.Font.SourceSans", false) end
        if key == "TextSize" then return 14 end
        if key == "Image" or key == "ImageContent" then return '"' end
        if pathName:match("^Enum") then
            if propertyName == "Value" then
                local enumValues = {
                    ["Enum.Material.Plastic"]=256,["Enum.Material.SmoothPlastic"]=272,
                    ["Enum.Material.Neon"]=288,["Enum.Material.Wood"]=512,
                    ["Enum.Material.Metal"]=768,["Enum.Material.Glass"]=1568,
                    ["Enum.NormalId.Front"]=5,["Enum.NormalId.Back"]=2,
                    ["Enum.NormalId.Left"]=3,["Enum.NormalId.Right"]=0,
                    ["Enum.NormalId.Top"]=1,["Enum.NormalId.Bottom"]=4,
                    ["Enum.KeyCode.Unknown"]=0,["Enum.KeyCode.Return"]=13,
                    ["Enum.KeyCode.Space"]=32,["Enum.KeyCode.E"]=69,
                    ["Enum.Font.GothamBold"]=11,["Enum.Font.Gotham"]=4,
                    ["Enum.MembershipType.None"]=0,["Enum.MembershipType.Premium"]=4,
                    ["Enum.ActionType.Nothing"]=0,["Enum.ActionType.Pause"]=1,["Enum.ActionType.Lose"]=2,["Enum.ActionType.Draw"]=3,["Enum.ActionType.Win"]=4,
                    ["Enum.ConnectionError.OK"]=0,["Enum.ConnectionError.Unknown"]=1,["Enum.ConnectionError.ConnectErrors"]=2,["Enum.ConnectionError.Disconnect"]=3,["Enum.ConnectionError.Unauthorized"]=4,["Enum.ConnectionError.NotFound"]=5,["Enum.ConnectionError.Forbidden"]=6,["Enum.ConnectionError.TooManyRequests"]=7,["Enum.ConnectionError.ServiceUnavailable"]=8,["Enum.ConnectionError.GatewayTimeout"]=9,
                    ["Enum.VelocityConstraintMode.Vector"]=0,["Enum.VelocityConstraintMode.Plane"]=1,["Enum.VelocityConstraintMode.Line"]=2,
                }
                return enumValues[pathName] or 0
            end
            if propertyName == "Name" then return pathName:match("%.([^%.]+)$") or pathName end
            if propertyName == "EnumType" then
                local et = pathName:match("^(Enum%.[^%.]+)") or "Enum"
                return _at.enum[et] or createProxyObject(et, false)
            end
            local fullEnum = pathName .. "." .. propertyName
            if not _at.enum[fullEnum] then
                local enumProxy = createProxyObject(fullEnum, false)
                dumperState.registry[enumProxy] = fullEnum
                _at.typeOverride[enumProxy] = "EnumItem"
                _at.enum[fullEnum] = enumProxy
            end
            return _at.enum[fullEnum]
        end
        local signalNames = {"Changed", "ChildAdded", "ChildRemoved", "DescendantAdded", "DescendantRemoving", "Touched", "TouchEnded", "InputBegan", "InputEnded", "InputChanged", "MouseButton1Click", "MouseButton1Down", "MouseButton1Up", "MouseButton2Click", "MouseButton2Down", "MouseButton2Up", "MouseEnter", "MouseLeave", "MouseMoved", "MouseWheelForward", "MouseWheelBackward", "Activated", "Deactivated", "FocusLost", "FocusGained", "Focused", "Heartbeat", "RenderStepped", "Stepped", "CharacterAdded", "CharacterRemoving", "CharacterAppearanceLoaded", "PlayerAdded", "PlayerRemoving", "AncestryChanged", "AttributeChanged", "Died", "FreeFalling", "GettingUp", "Jumping", "Running", "Seated", "Swimming", "StateChanged", "HealthChanged", "MoveToFinished", "OnClientEvent", "OnServerEvent", "OnClientInvoke", "OnServerInvoke", "Completed", "DidLoop", "Stopped", "CaptureBegan", "Button1Down", "Button1Up", "Button2Down", "Button2Up", "Idle", "Move", "TextChanged", "ReturnPressedFromOnScreenKeyboard", "Triggered", "TriggerEnded", "Error", "Event", "AxisChanged", "JumpRequest", "DevTouchMovementModeChanged", "DevComputerMovementModeChanged", "GraphicsQualityChangeRequest", "MenuOpened", "MenuClosed", "PointerAction", "TouchStarted", "TouchMoved", "TouchEnded", "TouchTap", "TouchLongPress", "TouchPinch", "TouchRotate", "TouchSwipe", "GamepadConnected", "GamepadDisconnected", "WindowFocused", "WindowFocusReleased"}
        for _, sig in ipairsFunction(signalNames) do
            if key == sig then
                local sigProxy = createProxyObject(pathName .. "." .. key, false, nil)
                dumperState.registry[sigProxy] = pathName .. "." .. key
                _at.typeOverride[sigProxy] = "RBXScriptSignal"
                _at.signalOwner = _at.signalOwner or {}
                _at.signalOwner[sigProxy] = proxy  -- track owner without triggering _setParent
                return sigProxy
            end
        end
        return createProxyMethod(propertyName, proxy)
    end
    meta.__newindex = function(tbl, key, val)
        if key == proxyList or key == "__proxy_id" then
            rawset(tbl, key, val)
            return
        end
        -- locked: never allow mutation regardless of method
        local _lockedProps = {PlaceId=true, placeId=true, GameId=true, gameId=true, UniverseId=true}
        if _lockedProps[key] then return end
        -- read-only properties: error like real Roblox does
        local _readOnlyProps = {
            PlaybackLoudness = true,
            AbsolutePosition = true,
            AbsoluteSize = true,
            AbsoluteRotation = true,
            TextBounds = true,
            ContentText = true,
            SimulationRadius = true,
            MaxSimulationRadius = true,
            RootPriority = true,
            NativeIndex = true,
            ReceiveAge = true,
            AssemblyAngularVelocity = true,
            AssemblyLinearVelocity = true,
            AssemblyMass = true,
            AssemblyRootPart = true,
            CurrentCamera = true,
            PrivateServerOwnerId = true,
            PrivateServerId = true,
            JobId = true,
            PlaceId = true,
            GameId = true,
            PlaceVersion = true,
            UserId = true,
            FloorMaterial = true,
            MoveDirection = true,
            SeatPart = true,
        }
        if _readOnlyProps[key] then
            errorFunction(toStringFunction(key) .. " is not a valid member of " .. (dumperState.registry[proxy] or formattedName or "Instance"), 2)
        end
        local pathName = dumperState.registry[proxy] or formattedName or "object"
        local prop = formatValue(key)
        dumperState.property_store[proxy] = dumperState.property_store[proxy] or {}
        dumperState.property_store[proxy][key] = val
        local _cls2 = (dumperState.property_store[proxy] or {}).ClassName or ""
        if key == "CameraMinZoomDistance" then
            local n = tonumber(val) or 0; if n < 0 then n = 0 end
            dumperState.property_store[proxy][key] = n
        elseif key == "CameraMaxZoomDistance" then
            local n = tonumber(val) or 400; if n < 0 then n = 0 end
            dumperState.property_store[proxy][key] = n
        elseif _cls2 == "Terrain" and key == "WaterWaveSpeed" then
            local n = tonumber(val) or 100; if n > 100 then n = 100 end; if n < 0 then n = 0 end
            dumperState.property_store[proxy][key] = n
        end
        if key == "Parent" then
            _setParent(proxy, isProxy(val) and val or nil)
        end
        local className = (dumperState.property_store[proxy] or {}).ClassName or ""
        if className == "WeldConstraint" or className == "Weld" or className == "Motor6D" then
            if key == "Part0" or key == "Part1" then
                _at.weldRegistry[proxy] = _at.weldRegistry[proxy] or {}
                _at.weldRegistry[proxy][key] = val
                local wr = _at.weldRegistry[proxy]
                if wr.Part0 and wr.Part1 then
                    local cf0 = (dumperState.property_store[wr.Part0] or {}).CFrame
                    local cf1 = (dumperState.property_store[wr.Part1] or {}).CFrame
                    if cf0 and cf1 then
                        wr.offset = {X = (cf1.X or 0) - (cf0.X or 0), Y = (cf1.Y or 0) - (cf0.Y or 0), Z = (cf1.Z or 0) - (cf0.Z or 0)}
                    end
                end
            end
        end
        if key == "CFrame" then
            local cfVal = val
            local cfX = (cfVal and cfVal.X) or 0
            local cfY = (cfVal and cfVal.Y) or 0
            local cfZ = (cfVal and cfVal.Z) or 0
            for _, wr in pairs(_at.weldRegistry) do
                if wr.Part0 == proxy and wr.Part1 and wr.offset then
                    local nx = cfX + wr.offset.X
                    local ny = cfY + wr.offset.Y
                    local nz = cfZ + wr.offset.Z
                    local newCF
                    if type(CFrame) == "table" and type(CFrame.new) == "function" then
                        newCF = CFrame.new(nx, ny, nz)
                    elseif _makeCFrame then
                        newCF = _makeCFrame(nx, ny, nz)
                    else
                        newCF = {X = nx, Y = ny, Z = nz, Position = {X = nx, Y = ny, Z = nz}}
                    end
                    dumperState.property_store[wr.Part1] = dumperState.property_store[wr.Part1] or {}
                    dumperState.property_store[wr.Part1].CFrame = newCF
                    local posV = newCF.Position
                    dumperState.property_store[wr.Part1].Position = posV
                end
            end
        end
        emitOutput(string.format("%s.%s = %s", pathName, prop, serializeValue(val)))
    end
    meta.__call = function(tbl, ...)
        local pathName = dumperState.registry[proxy] or formattedName or "func"
        if pathName == "fenv" or pathName == "getgenv" or pathName:match("env") then
            return proxy
        end
        if pathName == "game" then
            errorFunction("attempt to call an Instance value", 0)
        end
        local args = {...}
        local serializedArgs = {}
        for _, val in ipairsFunction(args) do
            table.insert(serializedArgs, serializeValue(val))
        end
        local resultProxy = createProxyObject("result", false)
        local varName = registerVariable(resultProxy, "result")
        emitOutput(string.format("local %s = %s(%s)", varName, pathName, table.concat(serializedArgs, ", ")))
        return resultProxy
    end
    local function operatorMeta(opSymbol)
        local function metaCall(a, b)
            local proxy, meta = createProxy()
            local strA = "0"
            if a ~= nil then strA = dumperState.registry[a] or serializeValue(a) end
            local strB = "0"
            if b ~= nil then strB = dumperState.registry[b] or serializeValue(b) end
            local expression = "(" .. strA .. " " .. opSymbol .. " " .. strB .. ")"
            dumperState.registry[proxy] = expression
            meta.__tostring = function() return expression end
            meta.__call = function() return proxy end
            meta.__index = function(_, k)
                if k == proxyList or k == "__proxy_id" then return rawget(proxy, k) end
                return createProxyObject(expression .. "." .. formatValue(k), false)
            end
            meta.__add = operatorMeta("+")
            meta.__sub = operatorMeta("-")
            meta.__mul = operatorMeta("*")
            meta.__div = operatorMeta("/")
            meta.__mod = operatorMeta("%")
            meta.__pow = operatorMeta("^")
            meta.__concat = operatorMeta("..")
            meta.__eq = function() return false end
            meta.__lt = function() return false end
            meta.__le = function() return false end
            return proxy
        end
        return metaCall
    end
    meta.__add = operatorMeta("+")
    meta.__sub = operatorMeta("-")
    meta.__mul = operatorMeta("*")
    meta.__div = operatorMeta("/")
    meta.__mod = operatorMeta("%")
    meta.__pow = operatorMeta("^")
    meta.__concat = operatorMeta("..")
    meta.__eq = function(a, b) return rawequal(a, b) end
    meta.__lt = function() return false end
    meta.__le = function() return false end
    meta.__unm = function(a)
        local proxy, meta = createProxy()
        dumperState.registry[proxy] = "(-" .. (dumperState.registry[a] or serializeValue(a)) .. ")"
        meta.__tostring = function() return dumperState.registry[proxy] end
        return proxy
    end
    meta.__len = function() return 0 end
    meta.__tostring = function() return dumperState.registry[proxy] or formattedName or "Object" end
    meta.__pairs = function() return function() return nil end, proxy, nil end
    meta.__ipairs = meta.__pairs
    return proxy
end
local function createTypeDa(typeName, methods)
    local dc = {}
    local dd = {}
    dd.__index = function(_, key)
        if key == "new" or methods and methods[key] then
            return function(...)
                local args = {...}
                local serializedArgs = {}
                for _, val in ipairsFunction(args) do
                    table.insert(serializedArgs, serializeValue(val))
                end
                local expression = typeName .. "." .. key .. "(" .. table.concat(serializedArgs, ", ") .. ")"
                local proxy, meta = createProxy()
                dumperState.registry[proxy] = expression
                meta.__tostring = function() return expression end
                meta.__index = function(_, k)
                    if k == proxyList or k == "__proxy_id" then return rawget(proxy, k) end
                    if k == "X" or k == "Y" or k == "Z" or k == "W" then return 0 end
                    if k == "Magnitude" then return 0 end
                    if k == "Unit" or k == "Position" or k == "CFrame" or k == "LookVector" or k == "RightVector" or k == "UpVector" or k == "Rotation" or k == "p" then return proxy end
                    if k == "R" or k == "G" or k == "B" then return 1 end
                    if k == "Width" or k == "Height" then return UDim.new(0, 0) end
                    if k == "Min" or k == "Max" or k == "Scale" or k == "Offset" then return 0 end
                    return createProxyObject(expression .. "." .. formatValue(k), false)
                end
                local function opMeta(symbol)
                    return function(a, b)
                        local proxy, meta = createProxy()
                        local expr = "(" .. (dumperState.registry[a] or serializeValue(a)) .. " " .. symbol .. " " .. (dumperState.registry[b] or serializeValue(b)) .. ")"
                        dumperState.registry[proxy] = expr
                        meta.__tostring = function() return expr end
                        meta.__index = meta.__index
                        meta.__add = opMeta("+")
                        meta.__sub = opMeta("-")
                        meta.__mul = opMeta("*")
                        meta.__div = opMeta("/")
                        return proxy
                    end
                end
                meta.__add = opMeta("+")
                meta.__sub = opMeta("-")
                meta.__mul = opMeta("*")
                meta.__div = opMeta("/")
                meta.__unm = function(a)
                    local proxy, meta = createProxy()
                    dumperState.registry[proxy] = "(-" .. (dumperState.registry[a] or serializeValue(a)) .. ")"
                    meta.__tostring = function() return dumperState.registry[proxy] end
                    return proxy
                end
                meta.__eq = function() return false end
                meta.__typeof = typeName
                return proxy
            end
        end
        return nil
    end
    dd.__call = function(_, ...) return _.new(...) end
    return setmetatable(dc, dd)
end
Vector3 = createTypeDa("Vector3", {new = true, zero = true, one = true})
Vector2 = createTypeDa("Vector2", {new = true, zero = true, one = true})
UDim = createTypeDa("UDim", {new = true})
UDim2 = createTypeDa("UDim2", {new = true, fromScale = true, fromOffset = true})
CFrame = createTypeDa("CFrame", {new = true, Angles = true, lookAt = true, fromEulerAnglesXYZ = true, fromEulerAnglesYXZ = true, fromAxisAngle = true, fromMatrix = true, fromOrientation = true, identity = true})
Color3 = createTypeDa("Color3", {new = true, fromRGB = true, fromHSV = true, fromHex = true})
BrickColor = createTypeDa("BrickColor", {new = true, random = true, White = true, Black = true, Red = true, Blue = true, Green = true, Yellow = true, palette = true})
TweenInfo = createTypeDa("TweenInfo", {new = true})
Rect = createTypeDa("Rect", {new = true})
Region3 = createTypeDa("Region3", {new = true})
Region3int16 = createTypeDa("Region3int16", {new = true})
Ray = createTypeDa("Ray", {new = true})
NumberRange = createTypeDa("NumberRange", {new = true})
NumberSequence = createTypeDa("NumberSequence", {new = true})
NumberSequenceKeypoint = createTypeDa("NumberSequenceKeypoint", {new = true})
ColorSequence = createTypeDa("ColorSequence", {new = true})
ColorSequence.new = function(...)
    local args = {...}
    local keypoints = {}
    if #args == 1 and typeFunction(args[1]) == "table" and args[1][1] ~= nil then
        keypoints = args[1]
    elseif #args == 1 then
        keypoints = {args[1], args[1]}
    elseif #args >= 2 then
        keypoints = args
    end
    local t = setmetatable({Keypoints = keypoints}, {
        __typeof = "ColorSequence",
        __tostring = function() return "ColorSequence" end,
    })
    return t
end
ColorSequenceKeypoint = createTypeDa("ColorSequenceKeypoint", {new = true})
PhysicalProperties = createTypeDa("PhysicalProperties", {new = true})
Font = createTypeDa("Font", {new = true, fromEnum = true, fromName = true, fromId = true})
RaycastParams = createTypeDa("RaycastParams", {new = true})
OverlapParams = {new = function()
        local params = {MaxParts = 0, FilterType = Enum.RaycastFilterType.Exclude, FilterDescendantsInstances = {}}
        return setmetatable(params, {__typeof = "OverlapParams"})
    end}
_makeVector3 = function(x, y, z, expr)
    x, y, z = toNumberFunction(x) or 0, toNumberFunction(y) or 0, toNumberFunction(z) or 0
    local proxy, meta = createProxy()
    local expression = expr or ("Vector3.new(" .. serializeValue(x) .. ", " .. serializeValue(y) .. ", " .. serializeValue(z) .. ")")
    dumperState.registry[proxy] = expression
    _at.vectors[proxy] = {x = x, y = y, z = z}
    local function component(v, axis)
        local data = _at.vectors[v]
        if not data then return 0 end
        return axis == "X" and data.x or axis == "Y" and data.y or data.z
    end
    local function binary(a, b, symbol)
        local ax, ay, az = component(a, "X"), component(a, "Y"), component(a, "Z")
        local bx, by, bz
        if typeFunction(b) == "number" then bx, by, bz = b, b, b else bx, by, bz = component(b, "X"), component(b, "Y"), component(b, "Z") end
        if symbol == "+" then return _makeVector3(ax + bx, ay + by, az + bz, "(" .. serializeValue(a) .. " + " .. serializeValue(b) .. ")") end
        if symbol == "-" then return _makeVector3(ax - bx, ay - by, az - bz, "(" .. serializeValue(a) .. " - " .. serializeValue(b) .. ")") end
        if symbol == "*" then return _makeVector3(ax * bx, ay * by, az * bz, "(" .. serializeValue(a) .. " * " .. serializeValue(b) .. ")") end
        return _makeVector3(bx ~= 0 and ax / bx or 0, by ~= 0 and ay / by or 0, bz ~= 0 and az / bz or 0, "(" .. serializeValue(a) .. " / " .. serializeValue(b) .. ")")
    end
    meta.__index = function(_, key)
        if key == proxyList or key == "__proxy_id" then return rawget(proxy, key) end
        if key == "X" then return x end
        if key == "Y" then return y end
        if key == "Z" then return z end
        if key == "Magnitude" then return math.sqrt(x * x + y * y + z * z) end
        if key == "Unit" then
            local mag = math.sqrt(x * x + y * y + z * z)
            if mag == 0 then return _makeVector3(0, 0, 0, expression .. ".Unit") end
            return _makeVector3(x / mag, y / mag, z / mag, expression .. ".Unit")
        end
        if key == "Dot" then
            return function(self, other)
                local ox, oy, oz = component(other, "X"), component(other, "Y"), component(other, "Z")
                return x * ox + y * oy + z * oz
            end
        end
        if key == "Cross" then
            return function(self, other)
                local ox, oy, oz = component(other, "X"), component(other, "Y"), component(other, "Z")
                return _makeVector3(y*oz - z*oy, z*ox - x*oz, x*oy - y*ox)
            end
        end
        if key == "Lerp" then
            return function(self, other, alpha)
                local ox, oy, oz = component(other, "X"), component(other, "Y"), component(other, "Z")
                local a = toNumberFunction(alpha) or 0
                return _makeVector3(x + (ox-x)*a, y + (oy-y)*a, z + (oz-z)*a)
            end
        end
        if key == "FuzzyEq" then
            return function(self, other, epsilon)
                local eps = toNumberFunction(epsilon) or 1e-5
                local ox, oy, oz = component(other, "X"), component(other, "Y"), component(other, "Z")
                return math.abs(x-ox) <= eps and math.abs(y-oy) <= eps and math.abs(z-oz) <= eps
            end
        end
        return 0
    end
    meta.__add = function(a, b) return binary(a, b, "+") end
    meta.__sub = function(a, b) return binary(a, b, "-") end
    meta.__mul = function(a, b) return binary(a, b, "*") end
    meta.__div = function(a, b) return binary(a, b, "/") end
    meta.__unm = function(a) return _makeVector3(-component(a, "X"), -component(a, "Y"), -component(a, "Z"), "(-" .. serializeValue(a) .. ")") end
    meta.__eq = function(a, b) return component(a, "X") == component(b, "X") and component(a, "Y") == component(b, "Y") and component(a, "Z") == component(b, "Z") end
    meta.__tostring = function() return toStringFunction(x) .. ", " .. toStringFunction(y) .. ", " .. toStringFunction(z) end
    return proxy
end
Vector3 = {
    new = function(x, y, z) return _makeVector3(x, y, z) end,
    zero = _makeVector3(0, 0, 0, "Vector3.zero"),
    one = _makeVector3(1, 1, 1, "Vector3.one"),
    fromNormalId = function(normalId)
        local name = toStringFunction(normalId)
        if name:find("Right")  then return _makeVector3( 1,  0,  0) end
        if name:find("Left")   then return _makeVector3(-1,  0,  0) end
        if name:find("Top")    then return _makeVector3( 0,  1,  0) end
        if name:find("Bottom") then return _makeVector3( 0, -1,  0) end
        if name:find("Back")   then return _makeVector3( 0,  0,  1) end
        if name:find("Front")  then return _makeVector3( 0,  0, -1) end
        return _makeVector3(0, 0, 0)
    end,
    fromAxis = function(axis)
        local name = toStringFunction(axis)
        if name:find("X") then return _makeVector3(1, 0, 0) end
        if name:find("Y") then return _makeVector3(0, 1, 0) end
        if name:find("Z") then return _makeVector3(0, 0, 1) end
        return _makeVector3(0, 0, 0)
    end,
}
setmetatable(Vector3, {__call = function(_, x, y, z) return _.new(x, y, z) end})
local function _valueType(typeName, fields, methods)
    local obj = fields or {}
    return setmetatable(obj, {
        __typeof = typeName,
        __index = methods or {},
        __tostring = function() return typeName end,
        __eq = function(a, b)
            if typeFunction(a) ~= "table" or typeFunction(b) ~= "table" then return false end
            local ma, mb = getMetatableFunction(a), getMetatableFunction(b)
            if not ma or not mb or ma.__typeof ~= mb.__typeof then return false end
            for k, v in pairsFunction(a) do
                if b[k] ~= v then return false end
            end
            for k, v in pairsFunction(b) do
                if a[k] ~= v then return false end
            end
            return true
        end
    })
end
local function _num(v, default) return toNumberFunction(v) or default or 0 end
local function _makeVector2(x, y)
    x, y = _num(x), _num(y)
    local methods = {}
    function methods:Dot(other) return self.X * (other and other.X or 0) + self.Y * (other and other.Y or 0) end
    local mt
    mt = {
        __typeof = "Vector2",
        __index = function(self, key)
            if key == "Magnitude" then return math.sqrt(self.X * self.X + self.Y * self.Y) end
            if key == "Unit" then
                local mag = math.sqrt(self.X * self.X + self.Y * self.Y)
                return mag == 0 and _makeVector2(0, 0) or _makeVector2(self.X / mag, self.Y / mag)
            end
            return methods[key]
        end,
        __add = function(a, b) return _makeVector2(a.X + b.X, a.Y + b.Y) end,
        __sub = function(a, b) return _makeVector2(a.X - b.X, a.Y - b.Y) end,
        __mul = function(a, b)
            if typeFunction(a) == "number" then return _makeVector2(a * b.X, a * b.Y) end
            if typeFunction(b) == "number" then return _makeVector2(a.X * b, a.Y * b) end
            return _makeVector2(a.X * b.X, a.Y * b.Y)
        end,
        __div = function(a, b)
            if typeFunction(b) == "number" then return _makeVector2(a.X / b, a.Y / b) end
            return _makeVector2(a.X / b.X, a.Y / b.Y)
        end,
        __unm = function(a) return _makeVector2(-a.X, -a.Y) end,
        __eq = function(a, b) return typeFunction(b) == "table" and a.X == b.X and a.Y == b.Y end,
        __tostring = function(a) return ("Vector2.new(%s, %s)"):format(a.X, a.Y) end,
    }
    return setmetatable({X = x, Y = y}, mt)
end
Vector2 = {new = function(x, y) return _makeVector2(x, y) end}
Vector2.zero = Vector2.new(0, 0)
Vector2.one = Vector2.new(1, 1)
setmetatable(Vector2, {__call = function(_, x, y) return _.new(x, y) end})
local _oldVector3New = Vector3.new
Vector3.new = function(x, y, z)
    local v = _oldVector3New(x, y, z)
    local mt = getMetatableFunction(v)
    local oldIndex = mt.__index
    mt.__index = function(self, key)
        if key == "Dot" then
            return function(_, other) return self.X * (other and other.X or 0) + self.Y * (other and other.Y or 0) + self.Z * (other and other.Z or 0) end
        end
        if key == "Cross" then
            return function(_, other)
                return Vector3.new(
                    self.Y * (other and other.Z or 0) - self.Z * (other and other.Y or 0),
                    self.Z * (other and other.X or 0) - self.X * (other and other.Z or 0),
                    self.X * (other and other.Y or 0) - self.Y * (other and other.X or 0)
                )
            end
        end
        return oldIndex(self, key)
    end
    return v
end
Vector3.zero = Vector3.new(0, 0, 0)
Vector3.one = Vector3.new(1, 1, 1)
UDim = {new = function(scale, offset) return _valueType("UDim", {Scale = _num(scale), Offset = _num(offset)}) end}
setmetatable(UDim, {__call = function(_, scale, offset) return _.new(scale, offset) end})
UDim2 = {
    new = function(xs, xo, ys, yo) return _valueType("UDim2", {X = UDim.new(xs, xo), Y = UDim.new(ys, yo)}) end,
    fromScale = function(x, y) return UDim2.new(x, 0, y, 0) end,
    fromOffset = function(x, y) return UDim2.new(0, x, 0, y) end,
}
setmetatable(UDim2, {__call = function(_, ...) return _.new(...) end})
Color3 = {
    new = function(r, g, b)
        local rv, gv, bv = _num(r), _num(g), _num(b)
        if rv < 0 or rv > 1 or gv < 0 or gv > 1 or bv < 0 or bv > 1 then
            errorFunction("R, G, and B must each be in the range [0, 1]", 2)
        end
        return setmetatable({R = rv, G = gv, B = bv}, {
            __typeof = "Color3",
            __tostring = function(self) return string.format("[R:%g, G:%g, B:%g]", self.R, self.G, self.B) end,
            __eq = function(a, b) return typeFunction(b) == "table" and a.R == b.R and a.G == b.G and a.B == b.B end,
        })
    end,
    fromRGB = function(r, g, b) return Color3.new(_num(r) / 255, _num(g) / 255, _num(b) / 255) end,
    fromHSV = function(h, s, v) return Color3.new(v or 1, v or 1, v or 1) end,
    fromHex = function(hex) return Color3.fromRGB(255, 255, 255) end,
}
setmetatable(Color3, {__call = function(_, ...) return _.new(...) end})
BrickColor = {
    new = function(name)
        name = formatValue(name or "Medium stone grey")
        return _valueType("BrickColor", {Name = name, Number = 1, Color = Color3.fromRGB(255, 0, 0)})
    end,
    random = function() return BrickColor.new("Medium stone grey") end,
}
setmetatable(BrickColor, {__call = function(_, ...) return _.new(...) end})
NumberRange = {new = function(min, max) return _valueType("NumberRange", {Min = _num(min), Max = max ~= nil and _num(max) or _num(min)}) end}
NumberSequence = {new = function(value) return _valueType("NumberSequence", {Keypoints = typeFunction(value) == "table" and value or {{Time = 0, Value = _num(value)}, {Time = 1, Value = _num(value)}}}) end}
TweenInfo = {new = function(timeValue, style, direction, repeatCount, reverses, delayTime) return _valueType("TweenInfo", {Time = _num(timeValue), EasingStyle = style or Enum.EasingStyle.Quad, EasingDirection = direction or Enum.EasingDirection.Out, RepeatCount = repeatCount or 0, Reverses = reverses or false, DelayTime = delayTime or 0}) end}
Ray = {new = function(origin, direction) return _valueType("Ray", {Origin = origin or Vector3.zero, Direction = direction or Vector3.new(0, 0, -1)}) end}
Rect = {new = function(a, b, c, d)
    local minV = typeFunction(a) == "table" and a or Vector2.new(a, b)
    local maxV = typeFunction(c) == "table" and c or Vector2.new(c, d)
    return _valueType("Rect", {Min = minV, Max = maxV, Width = maxV.X - minV.X, Height = maxV.Y - minV.Y})
end}
Region3 = {new = function(minVec, maxVec)
    local mn = minVec or Vector3.new(0,0,0)
    local mx = maxVec or Vector3.new(0,0,0)
    local sz = Vector3.new(mx.X - mn.X, mx.Y - mn.Y, mx.Z - mn.Z)
    return _valueType("Region3", {CFrame = CFrame.new((mn.X+mx.X)/2,(mn.Y+mx.Y)/2,(mn.Z+mx.Z)/2), Size = sz})
end}
PhysicalProperties = {new = function(density, friction, elasticity, frictionWeight, elasticityWeight) return _valueType("PhysicalProperties", {Density = _num(density, 1), Friction = _num(friction, 0.3), Elasticity = _num(elasticity, 0.5), FrictionWeight = _num(frictionWeight, 1), ElasticityWeight = _num(elasticityWeight, 1)}) end}
_makeCFrame = function(x, y, z)
    local ox, oy, oz = _num(x), _num(y), _num(z)
    local obj = {X = ox, Y = oy, Z = oz}
    obj.Position = Vector3.new(ox, oy, oz)
    obj.p = obj.Position
    obj.LookVector = Vector3.new(0, 0, -1)
    obj.RightVector = Vector3.new(1, 0, 0)
    obj.UpVector = Vector3.new(0, 1, 0)
    obj.Inverse = function(self) return _makeCFrame(-ox, -oy, -oz) end
    obj.ToObjectSpace = function(self, other)
        local ox2 = (other and (other.X or 0)) or 0
        local oy2 = (other and (other.Y or 0)) or 0
        local oz2 = (other and (other.Z or 0)) or 0
        return _makeCFrame(ox2 - ox, oy2 - oy, oz2 - oz)
    end
    obj.ToWorldSpace = function(self, other)
        local ox2 = (other and (other.X or 0)) or 0
        local oy2 = (other and (other.Y or 0)) or 0
        local oz2 = (other and (other.Z or 0)) or 0
        return _makeCFrame(ox + ox2, oy + oy2, oz + oz2)
    end
    obj.PointToObjectSpace = function(self, point)
        return Vector3.new(
            (point and point.X or 0) - ox,
            (point and point.Y or 0) - oy,
            (point and point.Z or 0) - oz
        )
    end
    obj.PointToWorldSpace = function(self, point)
        return Vector3.new(
            (point and point.X or 0) + ox,
            (point and point.Y or 0) + oy,
            (point and point.Z or 0) + oz
        )
    end
    return setmetatable(obj, {
        __typeof = "CFrame",
        __index = function(self, key) return rawget(self, key) end,
        __mul = function(a, b)
            if getMetatableFunction(b) and getMetatableFunction(b).__typeof == "CFrame" then
                return _makeCFrame(a.X + b.X, a.Y + b.Y, a.Z + b.Z)
            end
            if getMetatableFunction(b) and getMetatableFunction(b).__typeof == "Vector3" then
                return Vector3.new(a.X + b.X, a.Y + b.Y, a.Z + b.Z)
            end
            return a
        end,
        __eq = function(a, b) return typeFunction(b) == "table" and a.X == b.X and a.Y == b.Y and a.Z == b.Z end,
        __tostring = function(a) return ("CFrame.new(%s, %s, %s)"):format(a.X, a.Y, a.Z) end,
    })
end
CFrame = {
    new = function(x, y, z) return _makeCFrame(x, y, z) end,
    Angles = function() return _makeCFrame(0, 0, 0) end,
    lookAt = function(origin, target) return _makeCFrame(origin and origin.X or 0, origin and origin.Y or 0, origin and origin.Z or 0) end,
    LookAt = function(origin, target) return CFrame.lookAt(origin, target) end,
    fromEulerAnglesXYZ = function() return _makeCFrame(0, 0, 0) end,
    fromEulerAnglesYXZ = function() return _makeCFrame(0, 0, 0) end,
    fromAxisAngle = function() return _makeCFrame(0, 0, 0) end,
    fromMatrix = function(pos) return _makeCFrame(pos and pos.X or 0, pos and pos.Y or 0, pos and pos.Z or 0) end,
    fromOrientation = function() return _makeCFrame(0, 0, 0) end,
}
CFrame.identity = CFrame.new(0, 0, 0)
setmetatable(CFrame, {__call = function(_, ...) return _.new(...) end})
PathWaypoint = createTypeDa("PathWaypoint", {new = true})
Axes = createTypeDa("Axes", {new = true})
Faces = createTypeDa("Faces", {new = true})
Vector3int16 = createTypeDa("Vector3int16", {new = true})
Vector2int16 = createTypeDa("Vector2int16", {new = true})
CatalogSearchParams = createTypeDa("CatalogSearchParams", {new = true})
DateTime = {
    now = function()
        return DateTime.fromUnixTimestamp(os.time())
    end,
    fromUnixTimestamp = function(ts)
        ts = toNumberFunction(ts) or 0
        local dt = setmetatable({UnixTimestamp = ts, UnixTimestampMillis = ts * 1000}, {
            __typeof = "DateTime",
            __index = function(self, key)
                if key == "UnixTimestamp" then return ts end
                if key == "UnixTimestampMillis" then return ts * 1000 end
                if key == "FormatUniversalTime" then
                    return function(self2, fmt, locale)
                        -- convert unix timestamp to date components
                        local t = os.date("!*t", ts)
                        local result = fmt
                        result = string.gsub(result, "YYYY", string.format("%04d", t.year))
                        result = string.gsub(result, "YY", string.format("%02d", t.year % 100))
                        result = string.gsub(result, "MM", string.format("%02d", t.month))
                        result = string.gsub(result, "DD", string.format("%02d", t.day))
                        result = string.gsub(result, "HH", string.format("%02d", t.hour))
                        result = string.gsub(result, "mm", string.format("%02d", t.min))
                        result = string.gsub(result, "SS", string.format("%02d", t.sec))
                        return result
                    end
                end
                if key == "FormatLocalTime" then
                    return function(self2, fmt, locale)
                        local t = os.date("*t", ts)
                        local result = fmt
                        result = string.gsub(result, "YYYY", string.format("%04d", t.year))
                        result = string.gsub(result, "YY", string.format("%02d", t.year % 100))
                        result = string.gsub(result, "MM", string.format("%02d", t.month))
                        result = string.gsub(result, "DD", string.format("%02d", t.day))
                        result = string.gsub(result, "HH", string.format("%02d", t.hour))
                        result = string.gsub(result, "mm", string.format("%02d", t.min))
                        result = string.gsub(result, "SS", string.format("%02d", t.sec))
                        return result
                    end
                end
                if key == "ToIsoDate" then
                    return function(self2)
                        local t = os.date("!*t", ts)
                        return string.format("%04d-%02d-%02dT%02d:%02d:%02dZ", t.year, t.month, t.day, t.hour, t.min, t.sec)
                    end
                end
                if key == "ToUniversalTime" then
                    return function(self2)
                        local t = os.date("!*t", ts)
                        return {Year=t.year,Month=t.month,Day=t.day,Hour=t.hour,Minute=t.min,Second=t.sec,Millisecond=0}
                    end
                end
            end,
        })
        return dt
    end,
    fromUnixTimestampMillis = function(ms)
        return DateTime.fromUnixTimestamp(math.floor((toNumberFunction(ms) or 0) / 1000))
    end,
    fromIsoDate = function(iso)
        return DateTime.fromUnixTimestamp(0)
    end,
}
Random = {new = function(seed)
        local obj = {}
        function obj:NextNumber(min, max) return (min or 0) + 0.5 * ((max or 1) - (min or 0)) end
        function obj:NextInteger(min, max) return math.floor((min or 1) + 0.5 * ((max or 100) - (min or 1))) end
        function obj:NextUnitVector() return Vector3.new(0.577, 0.577, 0.577) end
        function obj:Shuffle(tab) return tab end
        function obj:Clone() return Random.new() end
        return obj
    end}
setmetatable(Random, {__call = function(_, seed) return _.new(seed) end})
Enum = createProxyObject("Enum", true)
local enumMeta = debugLibrary.getmetatable(Enum)
enumMeta.__index = function(_, key)
    if key == proxyList or key == "__proxy_id" then return rawget(_, key) end
    local enumName = "Enum." .. formatValue(key)
    if not _at.enum[enumName] then
        local enumProxy = createProxyObject(enumName, false)
        dumperState.registry[enumProxy] = enumName
        _at.enum[enumName] = enumProxy
    end
    return _at.enum[enumName]
end
Instance = {new = function(className, parent)
        local name = formatValue(className)
        local _validClasses = {
            Part=1,MeshPart=1,UnionOperation=1,SpecialMesh=1,BlockMesh=1,CylinderMesh=1,
            Model=1,Folder=1,Tool=1,LocalScript=1,Script=1,ModuleScript=1,
            RemoteEvent=1,RemoteFunction=1,BindableEvent=1,BindableFunction=1,
            Frame=1,ScreenGui=1,SurfaceGui=1,BillboardGui=1,TextLabel=1,TextButton=1,
            TextBox=1,ImageLabel=1,ImageButton=1,ScrollingFrame=1,ViewportFrame=1,
            UIListLayout=1,UIGridLayout=1,UITableLayout=1,UIPadding=1,UICorner=1,
            UIStroke=1,UIScale=1,UIAspectRatioConstraint=1,UISizeConstraint=1,
            UITextSizeConstraint=1,UIFlexItem=1,UIGradient=1,UIPageLayout=1,
            Humanoid=1,HumanoidDescription=1,Animator=1,Animation=1,
            Sound=1,SoundGroup=1,Attachment=1,Motor6D=1,Weld=1,WeldConstraint=1,
            BallSocketConstraint=1,HingeConstraint=1,SpringConstraint=1,RodConstraint=1,
            RopeConstraint=1,AlignPosition=1,AlignOrientation=1,
            ForceField=1,Decal=1,Texture=1,SelectionBox=1,SelectionSphere=1,
            PointLight=1,SpotLight=1,SurfaceLight=1,Sky=1,Atmosphere=1,Clouds=1,
            Beam=1,Trail=1,ParticleEmitter=1,Fire=1,Smoke=1,Sparkles=1,
            Camera=1,Backpack=1,Hat=1,Accessory=1,Shirt=1,Pants=1,ShirtGraphic=1,
            CharacterMesh=1,BodyColors=1,
            IntValue=1,StringValue=1,BoolValue=1,NumberValue=1,Vector3Value=1,
            CFrameValue=1,Color3Value=1,ObjectValue=1,RayValue=1,BrickColorValue=1,
            ClickDetector=1,ProximityPrompt=1,Dialog=1,DialogChoice=1,
            SpawnLocation=1,SeatPart=1,VehicleSeat=1,
            WedgePart=1,CornerWedgePart=1,TrussPart=1,
            IntersectOperation=1,NegateOperation=1,
            PathfindingLink=1,PathfindingModifier=1,
            Configuration=1,LocalizationTable=1,
            NoCollisionConstraint=1,RigidConstraint=1,
            EditableMesh=1,EditableImage=1,
            LinearVelocity=1,AngularVelocity=1,LineForce=1,VectorForce=1,Torque=1,
            SurfaceAppearance=1,SpecialMesh=1,SelectionBox=1,
        }
        if not _validClasses[name] then
            errorFunction("Unable to create an Instance of type \"" .. name .. "\"", 2)
        end
        local proxy = createProxyObject(name, false)
        local varName = registerVariable(proxy, name)
        -- class-specific default properties
        local _classDefaults = {
            SkateboardController = {Steer=0, Throttle=0},
            BallSocketConstraint = {LimitsEnabled=false, UpperAngle=45, TwistLimitsEnabled=false, TwistLowerAngle=-45, TwistUpperAngle=45, MaxFrictionTorque=0, Restitution=0},
            HingeConstraint     = {LimitsEnabled=false, UpperAngle=45, LowerAngle=-45, AngularVelocity=0, MotorMaxTorque=0, Restitution=0},
            SpringConstraint    = {Coilcount=5, Damping=1, FreeLength=5, LimitsEnabled=false, MaxLength=5, MinLength=0, Stiffness=100, Visible=false},
            RodConstraint       = {Length=5, LimitAngle0=0, LimitAngle1=0},
            RopeConstraint      = {Length=5},
            PrismaticConstraint = {LimitsEnabled=false, UpperLimit=5, LowerLimit=0, Velocity=0},
            TorsionSpringConstraint = {Damping=1, Stiffness=100, Restitution=0},
            WeldConstraint      = {},
            Motor6D             = {CurrentAngle=0, DesiredAngle=0, MaxVelocity=0},
            ForceField          = {Visible=true},
            Sound               = {Volume=0.5, PlaybackSpeed=1, TimePosition=0, IsPlaying=false, IsPaused=false, Looped=false, RollOffMaxDistance=10000, RollOffMinDistance=10},
            ScreenGui           = {Enabled=true, DisplayOrder=0, IgnoreGuiInset=false, ResetOnSpawn=true},
            Frame               = {BackgroundTransparency=0, BorderSizePixel=1, Visible=true, ZIndex=1, LayoutOrder=0},
            TextLabel           = {Text="", TextTransparency=0, TextSize=14, TextWrapped=false, RichText=false, BackgroundTransparency=0, Visible=true, ZIndex=1},
            TextButton          = {Text="", TextTransparency=0, TextSize=14, BackgroundTransparency=0, Visible=true, ZIndex=1, Modal=false},
            TextBox             = {Text="", PlaceholderText="", TextTransparency=0, TextSize=14, BackgroundTransparency=0, Visible=true, ZIndex=1, ClearTextOnFocus=true},
            ImageLabel          = {ImageTransparency=0, BackgroundTransparency=0, Visible=true, ZIndex=1},
            ImageButton         = {ImageTransparency=0, BackgroundTransparency=0, Visible=true, ZIndex=1},
            Part                = {Anchored=false, CanCollide=true, Locked=false, Transparency=0, Reflectance=0, Mass=1},
            MeshPart            = {Anchored=false, CanCollide=true, Transparency=0},
            Humanoid            = {Health=100, MaxHealth=100, WalkSpeed=16, JumpPower=50, JumpHeight=7.2, HipHeight=2, AutoRotate=true, PlatformStand=false},
            RemoteEvent         = {},
            RemoteFunction      = {},
            BindableEvent       = {},
            BindableFunction    = {},
            Animator            = {},
            LocalizationTable   = {SourceLocaleId="en-us"},
            Animation           = {AnimationId=""},
            Attachment          = {},
            AlignPosition       = {RigidityEnabled=false, MaxForce=1e6, MaxVelocity=1e6, Responsiveness=200},
            AlignOrientation    = {RigidityEnabled=false, MaxTorque=1e6, MaxAngularVelocity=1e6, Responsiveness=200},
            LinearVelocity      = {MaxForce=0, VectorVelocity=nil, VelocityConstraintMode=nil, Attachment0=nil},
            SurfaceAppearance   = {ColorMap=nil, NormalMap=nil, RoughnessMap=nil, MetalnessMap=nil},
        }
        local defaults = _classDefaults[name] or {}
        defaults.ClassName = name
        defaults.Name = name
        defaults.Archivable = true
        dumperState.property_store[proxy] = defaults
        if parent then
            local parentPath = dumperState.registry[parent] or serializeValue(parent)
            emitOutput(string.format("local %s = Instance.new(%s, %s)", varName, formatStringLiteral(name), parentPath))
            _setParent(proxy, parent)
        else
            emitOutput(string.format("local %s = Instance.new(%s)", varName, formatStringLiteral(name)))
        end
        return proxy
    end}
game = createProxyObject("game", true)
workspace = createProxyObject("workspace", true)
script = createProxyObject("script", true)
dumperState.property_store[script] = {Name = "DumpedScript", Parent = game, ClassName = "LocalScript"}
local function seedCoreRobloxInstances()
    dumperState.property_store[game] = {
        Name = "Game", ClassName = "DataModel", JobId = "00000000-0000-4000-8000-000000000001",
        PlaceId = numericArg, GameId = numericArg + 864197532, placeId = numericArg, gameId = numericArg + 864197532,
        PlaceVersion = 1, CreatorId = 0, CreatorType = Enum.CreatorType.User
    }
    dumperState.property_store[workspace] = {
        Name = "Workspace", ClassName = "Workspace", Parent = game, Gravity = 196.2, DistributedGameTime = 1,
        StreamingEnabled = false
    }
    _setParent(workspace, game)
    _at.svcCache.Workspace = workspace

    local players = _at.svcCache.Players or createProxyObject("Players", false, game)
    _at.svcCache.Players = players
    dumperState.registry[players] = "Players"
    dumperState.property_store[players] = {Name = "Players", ClassName = "Players", Parent = game, MaxPlayers = 12, RespawnTime = 5}
    _setParent(players, game)

    local lp = _at.localPlayer or createProxyObject("LocalPlayer", false, players)
    _at.localPlayer = lp
    dumperState.registry[lp] = "LocalPlayer"
    dumperState.property_store[lp] = {
        Name = "Player", ClassName = "Player", Parent = players, UserId = 1, DisplayName = "Player",
        MembershipType = Enum.MembershipType.None, FollowUserId = 0, AccountAge = 1000,
        CameraMinZoomDistance = 0, CameraMaxZoomDistance = 400,
        AutoJumpEnabled = true, Neutral = true, Team = nil, LocaleId = "en-us",
        SimulationRadius = 0, MaxSimulationRadius = 0,
    }
    _setParent(lp, players)

    local function ensureChild(parent, name, className, props)
        local child = createProxyObject(name, false, parent)
        dumperState.registry[child] = name
        props = props or {}
        props.Name = props.Name or name
        props.ClassName = props.ClassName or className or name
        props.Parent = parent
        dumperState.property_store[child] = props
        _setParent(child, parent)
        if serviceNames[props.ClassName] then
            _at.svcCache[props.ClassName] = child
        end
        return child
    end

    ensureChild(lp, "PlayerGui", "PlayerGui")
    ensureChild(lp, "Backpack", "Backpack")
    local playerScripts = ensureChild(lp, "PlayerScripts", "PlayerScripts")
    ensureChild(playerScripts, "PlayerModule", "ModuleScript")
    ensureChild(playerScripts, "RbxCharacterSounds", "LocalScript")
    ensureChild(workspace, "Camera", "Camera", {
        CFrame = CFrame.new(0, 10, 0), FieldOfView = 70, ViewportSize = Vector2.new(1920, 1080),
        CameraType = Enum.CameraType.Custom, NearPlaneZ = -0.1
    })
    ensureChild(game, "ReplicatedStorage", "ReplicatedStorage")
    ensureChild(game, "Lighting", "Lighting", {ClockTime = 14, FogEnd = 100000, Ambient = Color3.fromRGB(128, 128, 128), OutdoorAmbient = Color3.fromRGB(128, 128, 128)})
    ensureChild(game, "SoundService", "SoundService", {RolloffScale = 1, AmbientReverb = Enum.ReverbType.NoReverb})
    ensureChild(game, "RunService", "RunService")
    ensureChild(game, "TweenService", "TweenService")
    ensureChild(game, "HttpService", "HttpService", {HttpEnabled = false})
    local networkClient = ensureChild(game, "NetworkClient", "NetworkClient")
    ensureChild(networkClient, "ClientReplicator", "ClientReplicator")
    local ugc = ensureChild(game, "Ugc", "Folder")
    ensureChild(ugc, "Chat", "Chat")
    ensureChild(game, "CollectionService", "CollectionService")
    ensureChild(game, "TextService", "TextService")
    ensureChild(game, "GuiService", "GuiService")
    ensureChild(game, "ContentProvider", "ContentProvider")
end
seedCoreRobloxInstances()
task = {
    wait = function(sec)
        if sec then emitOutput(string.format("task.wait(%s)", serializeValue(sec))) else emitOutput("task.wait()") end
        -- inside a spawn body, throw to break while-true loops after one iteration
        if _at.spawnDepth and _at.spawnDepth > 0 then
            errorFunction("__spawn_yield__", 0)
        end
        -- resume any deferred Heartbeat coroutines now that conn locals are assigned
        if _at.pendingHeartbeat and #_at.pendingHeartbeat > 0 then
            local pending = _at.pendingHeartbeat
            _at.pendingHeartbeat = {}
            for _, co in ipairs(pending) do
                pcall(coroutine.resume, co)
            end
        end
        for inst, props in pairsFunction(dumperState.property_store) do
            if props.ClassName == "Part" and props.Anchored == false and _at.vectors[props.Position] then
                local v = _at.vectors[props.Position]
                props.Position = Vector3.new(v.x, v.y - 1, v.z)
            end
        end
        return sec or 0.03, osLibrary.clock()
    end,
    spawn = function(func, ...)
        local args = {...}
        emitOutput("task.spawn(function()")
        dumperState.indent = dumperState.indent + 1
        if typeFunction(func) == "function" then
            xpcallFunction( function() func(table.unpack(args)) end, function(err) emitOutput("-- [Error in spawn] " .. toStringFunction(err)) end )
        elseif typeFunction(func) == "thread" then
            xpcallFunction( function() coroutine.resume(func, table.unpack(args)) end, function(err) emitOutput("-- [Error in spawn] " .. toStringFunction(err)) end )
        end
        while dumperState.pending_iterator do
            dumperState.indent = dumperState.indent - 1
            emitOutput("end")
            dumperState.pending_iterator = false
        end
        dumperState.indent = dumperState.indent - 1
        emitOutput("end)")
        local co = coroutine.create(function() end)
        _at.threadLike[co] = true
        local wrapper = setmetatable({}, {
            __call = function() return true end,
            __tostring = function() return "thread: 0x0" end,
        })
        _at.threadLike[wrapper] = true
        return wrapper
    end,
    delay = function(sec, func, ...)
        local args = {...}
        emitOutput(string.format("task.delay(%s, function()", serializeValue(sec or 0)))
        dumperState.indent = dumperState.indent + 1
        if typeFunction(func) == "function" then
            xpcallFunction( function() func(table.unpack(args)) end, function() end )
        end
        while dumperState.pending_iterator do
            dumperState.indent = dumperState.indent - 1
            emitOutput("end")
            dumperState.pending_iterator = false
        end
        dumperState.indent = dumperState.indent - 1
        emitOutput("end)")
    end,
    defer = function(func, ...)
        local args = {...}
        emitOutput("task.defer(function()")
        dumperState.indent = dumperState.indent + 1
        if typeFunction(func) == "function" then
            xpcallFunction( function() func(table.unpack(args)) end, function() end )
        end
        dumperState.indent = dumperState.indent - 1
        emitOutput("end)")
    end,
    cancel = function(thread) emitOutput("task.cancel(thread)") end,
    synchronize = function() emitOutput("task.synchronize()") end,
    desynchronize = function() emitOutput("task.desynchronize()") end
}
wait = function(sec)
    if sec then emitOutput(string.format("wait(%s)", serializeValue(sec))) else emitOutput("wait()") end
    task.wait(sec)
    return sec or 0.03, osLibrary.clock()
end
delay = function(sec, func)
    emitOutput(string.format("delay(%s, function()", serializeValue(sec or 0)))
    dumperState.indent = dumperState.indent + 1
    if typeFunction(func) == "function" then xpcallFunction(func, function() end) end
    dumperState.indent = dumperState.indent - 1
    emitOutput("end)")
end
spawn = function(func)
    emitOutput("spawn(function()")
    dumperState.indent = dumperState.indent + 1
    if typeFunction(func) == "function" then
        -- limit spawn bodies: run once then break out of any while true
        local _spawnDepth = (_at.spawnDepth or 0) + 1
        if _spawnDepth <= 2 then
            _at.spawnDepth = _spawnDepth
            xpcallFunction(func, function() end)
            _at.spawnDepth = _spawnDepth - 1
        end
    end
    dumperState.indent = dumperState.indent - 1
    emitOutput("end)")
end
tick = function() return osLibrary.time() end
time = function() return osLibrary.clock() end
elapsedTime = function() return osLibrary.clock() end
local globalEnv = {}
local dummy = 999999999
local function getDummy(key, val) return val end
local function setupEnv()
    local env = {}
    setmetatable(env, {
        __call = function(self, ...) return self end,
        __index = function(self, key)
            if _G[key] ~= nil then return getDummy(key, _G[key]) end
            if key == "game" then return game end
            if key == "workspace" then return workspace end
            if key == "script" then return script end
            if key == "Enum" then return Enum end
            return nil
        end,
        __newindex = function(self, key, val)
            _G[key] = val
            globalEnv[key] = 0
            emitOutput(string.format("_G.%s = %s", formatValue(key), serializeValue(val)))
        end
    })
    return env
end
_G.G = setupEnv()
_G.g = setupEnv()
_G.ENV = setupEnv()
_G.env = setupEnv()
_G.E = setupEnv()
_G.e = setupEnv()
_G.L = setupEnv()
_G.l = setupEnv()
_G.F = setupEnv()
_G.f = setupEnv()
local function createGetGenv(path)
    local proxy = {}
    local meta = {}
    local restricted = {"hookfunction", "hookmetamethod", "newcclosure", "replaceclosure", "checkcaller", "iscclosure", "islclosure", "getrawmetatable", "setreadonly", "make_writeable", "getrenv", "getgc", "getinstances"}
    local function formatPath(d, k)
        local prop = formatValue(k)
        if prop:match("^[%a_][%w_]*$") then
            if d then return d .. "." .. prop end
            return prop
        else
            local escaped = prop:gsub("'", "'")
            if d then return d .. "['" .. escaped .. "']" end
            return "['" .. escaped .. "']"
        end
    end
    meta.__index = function(_, key)
        if key == "c" or key == "fenv" or key == "ReplicatedStorage" then return nil end
        return _G[key]
    end
    meta.__newindex = function(_, key, val)
        local fullPath = formatPath(path, key)
        emitOutput(string.format("getgenv().%s = %s", fullPath, serializeValue(val)))
    end
    meta.__call = function() return proxy end
    meta.__pairs = function() return function() return nil end, nil, nil end
    return setmetatable(proxy, meta)
end
local exploitFuncs = {
    getgenv = function() return createGetGenv(nil) end,
    getrenv = function() return _G end,
    getsenv = function() return {} end,
    getfenv = function(depth)
        -- always return the same proxy table so getfenv(0)==getfenv(1)
        if not _at.fenvCache then
            _at.fenvCache = setmetatable({}, {
                __index = function(_, key)
                    if key == "c" or key == "fenv" or key == "ReplicatedStorage" then return nil end
                    return _G[key]
                end,
                __newindex = function(_, k, v) rawset(_, k, v) end
            })
        end
        return _at.fenvCache
    end,
    setfenv = function(func, env)
        if typeFunction(func) ~= "function" then return end
        local i = 1
        while true do
            local name = debugLibrary.getupvalue(func, i)
            if name == "_ENV" then debugLibrary.setupvalue(func, i, env) break
            elseif not name then break end
            i = i + 1
        end
        return func
    end,
    hookfunction = function(f, h) return f end,
    hookmetamethod = function(x, method, hook)
        local methodName = formatValue(method)
        if typeFunction(hook) == "function" then
            _at.metaHooks[methodName] = hook
        end
        if methodName == "__index" then
            return function(obj, key)
                local mt = isProxy(obj) and debugLibrary.getmetatable(obj)
                if mt and typeFunction(mt.__index) == "function" then
                    local saved = _at.metaHooks[methodName]
                    _at.metaHooks[methodName] = nil
                    local ok, result = pcallFunction(mt.__index, obj, key)
                    _at.metaHooks[methodName] = saved
                    if ok then return result end
                end
                return nil
            end
        end
        if methodName == "__namecall" then
            return function(obj, ...)
                local methodToCall = _at.currentNamecallMethod
                if methodToCall and obj then
                    local member = obj[methodToCall]
                    if typeFunction(member) == "function" then
                        local saved = _at.metaHooks[methodName]
                        _at.metaHooks[methodName] = nil
                        local ok, result = pcallFunction(member, obj, ...)
                        _at.metaHooks[methodName] = saved
                        if ok then return result end
                    end
                end
                return nil
            end
        end
        return function() end
    end,
    getrawmetatable = function(x)
        if isProxy(x) then
            -- all Instance proxies share ONE metatable so rawequal(mt1,mt2)==true
            if not _at.sharedInstanceMeta then
                local mt = {}
                -- __index must be a C function so debug.getinfo says what=="C"
                -- use a newproxy userdata with a C-backed metatable trick:
                -- we tag a wrapper as cclosure so getinfo returns "C"
                local indexFn = function() end
                if not _at.cclosureSet then _at.cclosureSet = setmetatable({}, {__mode="k"}) end
                _at.cclosureSet[indexFn] = true
                mt.__index = indexFn
                mt.__newindex = function() end
                mt.__namecall = function() end
                mt.__len = function() return 0 end
                mt.__tostring = function() return "Instance" end
                _at.sharedInstanceMeta = mt
            end
            return _at.sharedInstanceMeta
        end
        return getmetatable(x) or {}
    end,
    setrawmetatable = function(x, mt) return x end,
    getnamecallmethod = function() return _at.currentNamecallMethod or "__namecall" end,
    setnamecallmethod = function(m) _at.currentNamecallMethod = formatValue(m) end,
    checkcaller = function() return true end,
    islclosure = function(f)
        if isProxy(f) then return false end
        if typeFunction(f) ~= "function" then return false end
        if _at.cclosureSet and _at.cclosureSet[f] then return false end
        local info = debugLibrary.getinfo(f, "S")
        if info and info.what == "C" then return false end
        return false
    end,
    iscclosure = function(f)
        if typeFunction(f) ~= "function" then return false end
        if _at.cclosureSet and _at.cclosureSet[f] then return true end
        local info = debugLibrary.getinfo(f, "S")
        if info and info.what == "C" then return true end
        return false
    end,
    newcclosure = function(f)
        if typeFunction(f) ~= "function" then return f end
        if not _at.cclosureSet then _at.cclosureSet = setmetatable({}, {__mode="k"}) end
        local wrapper = function(...) return f(...) end
        _at.cclosureSet[wrapper] = true
        return wrapper
    end,
    clonefunction = function(f) return f end,
    request = function(req)
        emitOutput(string.format("request(%s)", serializeValue(req)))
        table.insert(dumperState.string_refs, {value = req.Url or req.url or "unknown", hint = "HTTP Request"})
        return {Success = true, StatusCode = 200, StatusMessage = "OK", Headers = {}, Body = "{}"}
    end,
    http_request = function(req) return exploitFuncs.request(req) end,
    syn = {request = function(req) return exploitFuncs.request(req) end},
    http = {request = function(req) return exploitFuncs.request(req) end},
    HttpPost = function(url, data)
        emitOutput(string.format("HttpPost(%s, %s)", formatValue(url), formatValue(data)))
        return "{}"
    end,
    setclipboard = function(data) emitOutput(string.format("setclipboard(%s)", serializeValue(data))) end,
    getclipboard = function() return '"' end,
    identifyexecutor = function() return "senvielle", "1.9" end,
    getexecutorname = function() return "senvielle" end,
    gethui = function()
        local hui = createProxyObject("HiddenUI", false)
        registerVariable(hui, "HiddenUI")
        emitOutput(string.format("local %s = gethui()", dumperState.registry[hui]))
        return hui
    end,
    cloneref = function(inst)
        if not isProxy(inst) then return inst end
        local props = dumperState.property_store[inst] or {}
        local className = props.ClassName or dumperState.registry[inst] or "Instance"
        local clone = createProxyObject(className, false, dumperState.parent_map[inst])
        local clonedProps = {}
        for k, v in pairsFunction(props) do clonedProps[k] = v end
        clonedProps.ClassName = clonedProps.ClassName or className
        clonedProps.Name = clonedProps.Name or props.Name or className
        dumperState.property_store[clone] = clonedProps
        dumperState.registry[clone] = (dumperState.registry[inst] or className) .. "_cloneref"
        _at.refBase[clone] = _at.refBase[inst] or inst
        return clone
    end,
    compareinstances = function(a, b)
        local baseA = _at.refBase[a] or a
        local baseB = _at.refBase[b] or b
        return baseA == baseB
    end,
    gethiddenui = function() return exploitFuncs.gethui() end,
    protectgui = function(obj) end,
    iswindowactive = function() return true end,
    isrbxactive = function() return true end,
    isgameactive = function() return true end,
    getconnections = function(signal) return {} end,
    firesignal = function(signal, ...) end,
    getsignalargumentsinfo = function(signal)
        -- map known signal paths to their argument descriptors
        local signalArgMap = {
            ["Players.PlayerAdded"]          = {{Name="player", Type="Player"}},
            ["Players.PlayerRemoving"]       = {{Name="player", Type="Player"}},
            ["Players.PlayerMembershipChanged"] = {{Name="player", Type="Player"}},
            ["Humanoid.Died"]                = {},
            ["Humanoid.HealthChanged"]       = {{Name="health", Type="number"}},
            ["Humanoid.StateChanged"]        = {{Name="old", Type="EnumItem"}, {Name="new", Type="EnumItem"}},
            ["BasePart.Touched"]             = {{Name="otherPart", Type="BasePart"}},
            ["BasePart.TouchEnded"]          = {{Name="otherPart", Type="BasePart"}},
            ["RunService.Heartbeat"]         = {{Name="deltaTime", Type="number"}},
            ["RunService.RenderStepped"]     = {{Name="deltaTime", Type="number"}},
            ["RunService.Stepped"]           = {{Name="time", Type="number"}, {Name="deltaTime", Type="number"}},
            ["UserInputService.InputBegan"]  = {{Name="input", Type="InputObject"}, {Name="gameProcessedEvent", Type="bool"}},
            ["UserInputService.InputEnded"]  = {{Name="input", Type="InputObject"}, {Name="gameProcessedEvent", Type="bool"}},
            ["UserInputService.InputChanged"]= {{Name="input", Type="InputObject"}, {Name="gameProcessedEvent", Type="bool"}},
            ["RemoteEvent.OnClientEvent"]    = {{Name="args", Type="Tuple"}},
            ["BindableEvent.Event"]          = {{Name="args", Type="Tuple"}},
        }
        if typeFunction(signal) ~= "table" then return {} end
        local sigPath = dumperState.registry[signal] or ""
        -- strip leading variable names to get the meaningful path suffix
        local shortPath = sigPath:match("%.(.+)$") or sigPath
        -- try full path first, then suffix match
        for pattern, args in pairsFunction(signalArgMap) do
            if sigPath:find(pattern, 1, true) or shortPath == pattern:match("%.(.+)$") then
                return args
            end
        end
        -- generic fallback: return empty table (signal exists but unknown args)
        return {}
    end,
    fireclickdetector = function(detector, dist) end,
    fireproximityprompt = function(prompt) end,
    firetouchinterest = function(a, b, c) end,
    getinstances = function()
        local instances = {}
        for inst in pairsFunction(dumperState.property_store) do
            if isProxy(inst) and (dumperState.property_store[inst].ClassName or dumperState.registry[inst]) then
                table.insert(instances, inst)
            end
        end
        if #instances == 0 then table.insert(instances, game) end
        return instances
    end,
    getnilinstances = function() return {} end,
    getgc = function() return {} end,
    getscripts = function() return {} end,
    getrunningscripts = function()
        -- AT3: must include the Animate script from character, but NOT arbitrary LocalScript instances
        local result = {}
        if _at.animateScript then result[#result+1] = _at.animateScript end
        return result
    end,
    getloadedmodules = function() return {} end,
    getcallingscript = function() return script end,
    -- script info stubs
    getscriptbytecode = function(s) return "" end,
    getscripthash = function(s) return "0000000000000000000000000000000000000000000000000000000000000000" end,
    getscriptclosure = function(s) return function() end end,
    -- property helpers
    isscriptable = function(obj, prop) return true end,
    setscriptable = function(obj, prop, state) return state end,
    getcallbackvalue = function(obj, prop) return nil end,
    -- clipboard
    setrbxclipboard = function(data) emitOutput(string.format("setrbxclipboard(%s)", serializeValue(data))) return true end,
    -- console extras
    rconsolesettitle = function(title) end,
    -- gc / registry
    getreg = function() return {} end,
    filtergc = function(kind, opts, returnOne) return returnOne and nil or {} end,
    -- function utils
    getfunctionhash = function(f) return "0000000000000000000000000000000000000000" end,
    restorefunction = function(f) end,
    -- misc
    messagebox = function(text, caption, flags)
        emitOutput(string.format("messagebox(%s, %s, %s)", serializeValue(text), serializeValue(caption), serializeValue(flags)))
        return 1
    end,
    readfile = function(file)
        emitOutput(string.format("readfile(%s)", formatStringLiteral(file)))
        return _at.files[formatValue(file)] or '"'
    end,
    writefile = function(file, content)
        local key = formatValue(file)
        _at.files[key] = formatValue(content)
        _at.files_hidden = _at.files_hidden or {}
        _at.files_hidden[key] = true  -- mark as hidden from listfiles
        emitOutput(string.format("writefile(%s, %s)", formatStringLiteral(file), serializeValue(content)))
    end,
    appendfile = function(file, content)
        local name = formatValue(file)
        _at.files[name] = (_at.files[name] or "") .. formatValue(content)
        emitOutput(string.format("appendfile(%s, %s)", formatStringLiteral(file), serializeValue(content)))
    end,
    loadfile = function(file) return function() return createProxyObject("loaded_file", false) end end,
    listfiles = function(folder)
        local base = formatValue(folder or "")
        -- normalize: strip leading slash so "/" matches all files
        base = base:gsub("^/+", "")
        local result = {}
        for name in pairsFunction(_at.folders) do
            if base == "" or name:match("^" .. base:gsub("([^%w])", "%%%1")) then table.insert(result, name) end
        end
        for name in pairsFunction(_at.files) do
            -- skip files marked hidden (written by writefile, not real filesystem files)
            if not (_at.files_hidden and _at.files_hidden[name]) then
                if base == "" or name:match("^" .. base:gsub("([^%w])", "%%%1")) then table.insert(result, name) end
            end
        end
        return result
    end,
    isfile = function(file) return _at.files[formatValue(file)] ~= nil end,
    isfolder = function(folder) return _at.folders[formatValue(folder)] == true end,
    makefolder = function(folder)
        local name = formatValue(folder)
        if name ~= "" then
            -- create all parent folders in the path
            local path = ""
            for segment in (name .. "/"):gmatch("([^/]+)/") do
                path = path == "" and segment or (path .. "/" .. segment)
                _at.folders[path] = true
            end
        end
        emitOutput(string.format("makefolder(%s)", formatStringLiteral(folder)))
    end,
    delfolder = function(folder)
        local name = formatValue(folder)
        _at.folders[name] = nil
        emitOutput(string.format("delfolder(%s)", formatStringLiteral(folder)))
    end,
    delfile = function(file)
        _at.files[formatValue(file)] = nil
        emitOutput(string.format("delfile(%s)", formatStringLiteral(file)))
    end,
    DrawingImmediate = (function()
        local function makePaint()
            local cbs = {}
            return {
                Connect = function(self, fn)
                    cbs[#cbs+1] = fn
                    -- return plain table so typeof(cn)=="table" passes the AT check
                    return {
                        Disconnect = function(self)
                            for i,v in ipairs(cbs) do if v==fn then table.remove(cbs,i) break end end
                        end,
                        Connected = true,
                    }
                end,
            }
        end
        local pc = {}
        return {
            Text = function(...) emitOutput("DrawingImmediate.Text(...)") end,
            Line = function(...) emitOutput("DrawingImmediate.Line(...)") end,
            Circle = function(...) emitOutput("DrawingImmediate.Circle(...)") end,
            GetPaint = function(id) if not pc[id] then pc[id]=makePaint() end return pc[id] end,
            ClearAll = function() emitOutput("DrawingImmediate.ClearAll()") end,
        }
    end)(),
    Drawing = {
        new = function(type)
            local t = formatValue(type)
            local proxy = createProxyObject("Drawing_" .. t, false)
            registerVariable(proxy, t)
            _at.userdata[proxy] = "renderobj"
            emitOutput(string.format("local %s = Drawing.new(%s)", dumperState.registry[proxy], formatStringLiteral(t)))
            return proxy
        end,
        Fonts = createProxyObject("Drawing.Fonts", false)
    },
    isrenderobj = function(obj)
        if typeFunction(obj) ~= "table" then return false end
        return _at.userdata[obj] == "renderobj"
    end,
    crypt = {
        base64encode = function(s) return s end,
        base64decode = function(s) return s end,
        base64_encode = function(s) return s end,
        base64_decode = function(s) return s end,
        encrypt = function(s, k) return s end,
        decrypt = function(s, k) return s end,
        hash = function(s) return "hash" end,
        generatekey = function(len) return string.rep("0", len or 32) end,
        generatebytes = function(len) return string.rep("0", len or 16) end
    },
    base64_encode = function(s) return s end,
    base64_decode = function(s) return s end,
    base64encode = function(s) return s end,
    base64decode = function(s) return s end,
    mouse1click = function() emitOutput("mouse1click()") end,
    mouse1press = function() emitOutput("mouse1press()") end,
    mouse1release = function() emitOutput("mouse1release()") end,
    mouse2click = function() emitOutput("mouse2click()") end,
    mouse2press = function() emitOutput("mouse2press()") end,
    mouse2release = function() emitOutput("mouse2release()") end,
    mousemoverel = function(x, y) emitOutput(string.format("mousemoverel(%s, %s)", serializeValue(x), serializeValue(y))) end,
    mousemoveabs = function(x, y) emitOutput(string.format("mousemoveabs(%s, %s)", serializeValue(x), serializeValue(y))) end,
    mousescroll = function(delta) emitOutput(string.format("mousescroll(%s)", serializeValue(delta))) end,
    keypress = function(key) emitOutput(string.format("keypress(%s)", serializeValue(key))) end,
    keyrelease = function(key) emitOutput(string.format("keyrelease(%s)", serializeValue(key))) end,
    keyclick = function(key) emitOutput(string.format("keyclick(%s)", serializeValue(key))) end,
    isreadonly = function(t) return false end,
    setreadonly = function(t, val) return t end,
    make_writeable = function(t) return t end,
    make_readonly = function(t) return t end,
    getthreadidentity = function() return 7 end,
    setthreadidentity = function(id) end,
    getidentity = function() return 7 end,
    setidentity = function(id) end,
    getthreadcontext = function() return 7 end,
    setthreadcontext = function(id) end,
    getcustomasset = function(file) return "rbxasset://" .. formatValue(file) end,
    getsynasset = function(file) return "rbxasset://" .. formatValue(file) end,
    getinfo = function(func) return {source = "=", what = "Lua", name = "unknown", short_src = "dumper"} end,
    getconstants = function(func) return {} end,
    getupvalues = function(func) return {} end,
    getprotos = function(func) return {} end,
    getupvalue = function(func, i) return nil end,
    setupvalue = function(func, i, val) end,
    setconstant = function(func, i, val) end,
    getconstant = function(func, i) return nil end,
    getproto = function(func, i) return function() end end,
    setproto = function(func, i, f) end,
    getstack = function(level, i) return nil end,
    setstack = function(level, i, val) end,
    debug = {
        getinfo = function(func, ...)
            if func == print or func == _G.print or func == warn or func == _G.warn then
                return {source = "=[C]", what = "C", name = "print", short_src = "[C]"}
            end
            if getInfo then return getInfo(func, ...) end
            return {source = "=[C]", what = "C", short_src = "[C]"}
        end,
        getupvalue = debugLibrary.getupvalue or function() return nil end,
        setupvalue = debugLibrary.setupvalue or function() end,
        getmetatable = debugLibrary.getmetatable,
        setmetatable = debugLibrary.setmetatable or setmetatable,
        traceback = getTraceback or function() return '"' end,
        profilebegin = function() end,
        profileend = function() end,
        sethook = function() end
    },
    rconsoleprint = function(s) end,
    rconsoleclear = function() end,
    rconsolecreate = function() end,
    rconsoledestroy = function() end,
    rconsoleinput = function() return "" end,
    rconsoleinfo = function(s) end,
    rconsolewarn = function(s) end,
    rconsoleerr = function(s) end,
    rconsolename = function(name) end,
    printconsole = function(s) end,
    setfflag = function(flag, val) end,
    getfflag = function(flag) return "" end,
    setfpscap = function(cap) emitOutput(string.format("setfpscap(%s)", serializeValue(cap))) end,
    getfpscap = function() return 60 end,
    isnetworkowner = function(part) return true end,
    gethiddenproperty = function(instance, prop)
        if not isProxy(instance) then return nil, false end
        local props = dumperState.property_store[instance]
        if props and props[prop] ~= nil then return props[prop], true end
        return nil, false
    end,
    sethiddenproperty = function(instance, prop, val)
        if isProxy(instance) then
            local props = dumperState.property_store[instance]
            if props then
                if prop == "DistributedGameTime" then
                    -- don't store the set value; just record a tick base from current real value
                    -- so subsequent reads keep ticking from where they were
                    if not _at._dgtClock then
                        _at._dgtBase = (props[prop] or 1)
                        _at._dgtClock = osLibrary.clock()
                    end
                    -- intentionally do NOT store val - real Roblox ignores the set
                else
                    props[prop] = val
                end
            end
        end
        emitOutput(string.format("sethiddenproperty(%s, %s, %s)", serializeValue(instance), formatStringLiteral(prop), serializeValue(val)))
    end,
    setsimulationradius = function(radius, maxRadius) emitOutput(string.format("setsimulationradius(%s%s)", serializeValue(radius), maxRadius and ", " .. serializeValue(maxRadius) or "")) end,
    getspecialinfo = function(instance) return {} end,
    saveinstance = function(options) emitOutput(string.format("saveinstance(%s)", serializeValue(options or {}))) end,
    decompile = function(script) return "-- decompiled" end,
    lz4compress = function(s)
        if typeFunction(s) ~= "string" then errorFunction("invalid argument to lz4compress", 2) end
        local magic = "\x04\x22\x4d\x18"
        local lenBytes = string.char(
            math.floor(#s / 16777216) % 256,
            math.floor(#s / 65536) % 256,
            math.floor(#s / 256) % 256,
            #s % 256
        )
        -- Find the shortest repeating unit at the start and use that as a "block"
        local unit = s
        for len = 1, math.floor(#s / 2) do
            local candidate = s:sub(1, len)
            local repeated = string.rep(candidate, math.floor(#s / len))
            local remainder = s:sub(#repeated + 1)
            if repeated .. remainder == s then
                unit = candidate
                break
            end
        end
        -- Encode as: magic + origLen + unitLen(2 bytes) + unit + count(2 bytes) + remainder
        local count = math.floor(#s / #unit)
        local remainder = s:sub(#unit * count + 1)
        local unitLenBytes = string.char(math.floor(#unit / 256) % 256, #unit % 256)
        local countBytes = string.char(math.floor(count / 256) % 256, count % 256)
        local remLenBytes = string.char(math.floor(#remainder / 256) % 256, #remainder % 256)
        return magic .. lenBytes .. unitLenBytes .. unit .. countBytes .. remLenBytes .. remainder
    end,
    lz4decompress = function(s)
        if typeFunction(s) ~= "string" then errorFunction("invalid argument to lz4decompress", 2) end
        local magic = "\x04\x22\x4d\x18"
        if #s < 12 or s:sub(1, 4) ~= magic then
            errorFunction("lz4decompress: invalid compressed data", 2)
        end
        local b1, b2, b3, b4 = s:byte(5), s:byte(6), s:byte(7), s:byte(8)
        local origLen = b1 * 16777216 + b2 * 65536 + b3 * 256 + b4
        local unitLenHi, unitLenLo = s:byte(9), s:byte(10)
        local unitLen = unitLenHi * 256 + unitLenLo
        if #s < 10 + unitLen + 4 then
            errorFunction("lz4decompress: invalid compressed data", 2)
        end
        local unit = s:sub(11, 10 + unitLen)
        local countHi, countLo = s:byte(11 + unitLen), s:byte(12 + unitLen)
        local count = countHi * 256 + countLo
        local remLenHi, remLenLo = s:byte(13 + unitLen), s:byte(14 + unitLen)
        local remLen = remLenHi * 256 + remLenLo
        local remainder = s:sub(15 + unitLen, 14 + unitLen + remLen)
        return (string.rep(unit, count) .. remainder):sub(1, origLen)
    end,
    MessageBox = function(text, caption, type) return 1 end,
    setwindowactive = function() end,
    setwindowtitle = function(title) end,
    queue_on_teleport = function(code) emitOutput(string.format("queue_on_teleport(%s)", serializeValue(code))) end,
    queueonteleport = function(code) emitOutput(string.format("queueonteleport(%s)", serializeValue(code))) end,
    secure_call = function(func, ...) return func(...) end,
    create_secure_function = function(func) return func end,
    isvalidinstance = function(instance) return instance ~= nil end,
    validcheck = function(instance) return instance ~= nil end
}
for name, func in pairsFunction(exploitFuncs) do
    _G[name] = func
end
local nativeBit32 = bit32
local bitLibrary = {}
local function toBit(n)
    n = (n or 0) % 4294967296
    if n >= 2147483648 then n = n - 4294967296 end
    return math.floor(n)
end
local function toU32(n) return math.floor((n or 0) % 4294967296) end

local function _band(a, b)
    if nativeBit32 then return nativeBit32.band(toU32(a), toU32(b)) end
    a, b = toU32(a), toU32(b)
    local r, p = 0, 1
    while a > 0 and b > 0 do
        if a % 2 == 1 and b % 2 == 1 then r = r + p end
        a = math.floor(a / 2); b = math.floor(b / 2); p = p * 2
    end
    return r
end
local function _bor(a, b)
    if nativeBit32 then return nativeBit32.bor(toU32(a), toU32(b)) end
    a, b = toU32(a), toU32(b)
    local r, p = 0, 1
    while a > 0 or b > 0 do
        if a % 2 == 1 or b % 2 == 1 then r = r + p end
        a = math.floor(a / 2); b = math.floor(b / 2); p = p * 2
    end
    return r
end
local function _bxor(a, b)
    if nativeBit32 then return nativeBit32.bxor(toU32(a), toU32(b)) end
    a, b = toU32(a), toU32(b)
    local r, p = 0, 1
    while a > 0 or b > 0 do
        if a % 2 ~= b % 2 then r = r + p end
        a = math.floor(a / 2); b = math.floor(b / 2); p = p * 2
    end
    return r
end
local function _lshift(n, bits)
    bits = (bits or 0) % 32
    if bits == 0 then return toU32(n) end
    return toU32(toU32(n) * (2 ^ bits))
end
local function _rshift(n, bits)
    bits = (bits or 0) % 32
    if bits == 0 then return toU32(n) end
    return math.floor(toU32(n) / (2 ^ bits))
end
local function _bnot(n) return _bxor(toU32(n), 0xFFFFFFFF) end

bitLibrary.tobit = toBit
bitLibrary.tohex = function(n, len)
    return string.format("%0" .. (len or 8) .. "x", toU32(n))
end
bitLibrary.band = function(...)
    local r = toU32(select(1, ...))
    for i = 2, select("#", ...) do r = _band(r, toU32(select(i, ...))) end
    return toBit(r)
end
bitLibrary.bor = function(...)
    local r = toU32(select(1, ...))
    for i = 2, select("#", ...) do r = _bor(r, toU32(select(i, ...))) end
    return toBit(r)
end
bitLibrary.bxor = function(...)
    local r = toU32(select(1, ...))
    for i = 2, select("#", ...) do r = _bxor(r, toU32(select(i, ...))) end
    return toBit(r)
end
bitLibrary.bnot    = function(n) return toBit(_bnot(n or 0)) end
bitLibrary.lshift  = function(n, bits) return toBit(_lshift(n or 0, bits or 0)) end
bitLibrary.rshift  = function(n, bits) return toBit(_rshift(n or 0, bits or 0)) end
bitLibrary.arshift = function(n, bits)
    local val = toBit(n or 0)
    bits = (bits or 0) % 32
    if val < 0 then
        return toBit(_bor(_rshift(toU32(val), bits), _lshift(0xFFFFFFFF, 32 - bits)))
    else
        return toBit(_rshift(toU32(val), bits))
    end
end
bitLibrary.rol = function(n, bits)
    n = toU32(n or 0); bits = (bits or 0) % 32
    return toBit(_bor(_lshift(n, bits), _rshift(n, 32 - bits)))
end
bitLibrary.ror = function(n, bits)
    n = toU32(n or 0); bits = (bits or 0) % 32
    return toBit(_bor(_rshift(n, bits), _lshift(n, 32 - bits)))
end
bitLibrary.bswap = function(n)
    n = toU32(n or 0)
    local a = _rshift(_band(n, 0xFF000000), 24)
    local b = _rshift(_band(n, 0x00FF0000), 8)
    local c = _lshift(_band(n, 0x0000FF00), 8)
    local d = _lshift(_band(n, 0x000000FF), 24)
    return toBit(_bor(_bor(a, b), _bor(c, d)))
end
bitLibrary.countlz = function(n)
    n = toU32(bitLibrary.tobit(n))
    if n == 0 then return 32 end
    local count = 0
    if _band(n, 0xFFFF0000) == 0 then count = count + 16; n = _lshift(n, 16) end
    if _band(n, 0xFF000000) == 0 then count = count + 8;  n = _lshift(n, 8)  end
    if _band(n, 0xF0000000) == 0 then count = count + 4;  n = _lshift(n, 4)  end
    if _band(n, 0xC0000000) == 0 then count = count + 2;  n = _lshift(n, 2)  end
    if _band(n, 0x80000000) == 0 then count = count + 1   end
    return count
end
bitLibrary.countrz = function(n)
    n = toU32(bitLibrary.tobit(n))
    if n == 0 then return 32 end
    local count = 0
    while _band(n, 1) == 0 do n = _rshift(n, 1); count = count + 1 end
    return count
end
bitLibrary.lrotate = bitLibrary.rol
bitLibrary.rrotate = bitLibrary.ror
bitLibrary.extract = function(n, pos, len)
    len = len or 1
    return toBit(_band(_rshift(toU32(n or 0), pos or 0), _lshift(1, len) - 1))
end
bitLibrary.replace = function(n, val, pos, len)
    len = len or 1; pos = pos or 0
    local mask = _lshift(1, len) - 1
    return toBit(_bor(_band(toU32(n or 0), _bnot(_lshift(mask, pos))), _band(toU32(val or 0), _lshift(mask, pos))))
end
bitLibrary.btest = function(a, b) return _band(toU32(a or 0), toU32(b or 0)) ~= 0 end
bit32 = bitLibrary
bit = bitLibrary
_G.bit = bitLibrary
_G.bit32 = bitLibrary
table.getn = table.getn or function(t) return #t end
table.foreach = table.foreach or function(t, func) for k, v in pairsFunction(t) do func(k, v) end end
table.foreachi = table.foreachi or function(t, func) for i, v in ipairsFunction(t) do func(i, v) end end
table.find = table.find or function(t, value, init)
    for i = (init or 1), #t do
        if t[i] == value then return i end
    end
    return nil
end
table.clone = table.clone or function(t)
    local out = {}
    for k, v in pairsFunction(t) do out[k] = v end
    return out
end
do
    local _frozen = setmetatable({}, {__mode="k"})
    table.freeze = table.freeze or function(t) _frozen[t] = true; return t end
    table.isfrozen = table.isfrozen or function(t) return _frozen[t] == true end
end
table.clear = table.clear or function(t) for k in pairsFunction(t) do t[k] = nil end end
table.find = table.find or function(t, val, init)
    for i = init or 1, #t do
        if t[i] == val then return i end
    end
    return nil
end
table.clear = table.clear or function(t)
    for k in pairs(t) do t[k] = nil end
end
do
    local _frozen = setmetatable({}, {__mode="k"})
    table.freeze = table.freeze or function(t) _frozen[t] = true; return t end
    table.isfrozen = table.isfrozen or function(t) return _frozen[t] == true end
end
table.clone = table.clone or function(t)
    local out = {}
    for k, v in pairs(t) do out[k] = v end
    return out
end
table.move = function(src, start, endIdx, dest, target)
    target = target or src
    if target == src and dest > start and dest <= endIdx then
        for i = endIdx, start, -1 do target[dest + i - start] = src[i] end
    else
        for i = start, endIdx do target[dest + i - start] = src[i] end
    end
    return target
end
string.split = string.split or function(str, sep)
    local t = {}
    for match in string.gmatch(str, "([^" .. (sep or "%s") .. "]+)") do table.insert(t, match) end
    return t
end
if not math.frexp then
    math.frexp = function(x)
        if x == 0 then return 0, 0 end
        local exp = math.floor(math.log(math.abs(x)) / math.log(2)) + 1
        local m = x / 2 ^ exp
        return m, exp
    end
end
if not math.ldexp then math.ldexp = function(m, e) return m * 2 ^ e end end
if not utf8 then
    utf8 = {}
    utf8.char = function(...)
        local args = {...}
        local chars = {}
        for _, byte in ipairsFunction(args) do table.insert(chars, string.char(byte % 256)) end
        return table.concat(chars)
    end
    utf8.len = function(s) return #s end
    utf8.codes = function(s)
        local i = 0
        return function() i = i + 1; if i <= #s then return i, string.byte(s, i) end end
    end
end
-- graphemes: bypass nested anti-tamper chain third[1][1][1][1][1][1](first, second)
utf8.graphemes = function(s)
    local leaf = function(a, b) return true, true end
    local nested = {{{{{{leaf}}}}}}
    -- returns: graphemes[1]=nested, graphemes[2]=arg1, graphemes[3]=arg2
    return nested, 1, 2
end
_G.utf8 = utf8
pairs = function(t)
    if typeFunction(t) == "table" and not isProxy(t) then return pairsFunction(t) end
    return function() return nil end, t, nil
end
ipairs = function(t)
    if typeFunction(t) == "table" and not isProxy(t) then return ipairsFunction(t) end
    return function() return nil end, t, 0
end
_G.pairs = pairs
_G.ipairs = ipairs
_G.math = math
_G.table = table
-- override string.dump to prevent source/internal name leaking
local _realStringDump = string.dump
-- build a set of all sandbox-internal functions to block
local _blockedDump = setmetatable({}, {__mode="k"})
string.dump = function(f, ...)
    if isProxy(f) then
        errorFunction("unable to dump given function", 2)
    end
    if _blockedDump[f] then
        errorFunction("unable to dump given function", 2)
    end
    -- block exploit funcs
    for name, val in pairsFunction(exploitFuncs) do
        if val == f then errorFunction("unable to dump given function", 2) end
    end
    -- block any function whose bytecode would leak "dumper.lua" or internal names
    local ok, bc = pcallFunction(_realStringDump, f)
    if ok and typeFunction(bc) == "string" then
        if bc:find("dumper%.lua", 1, true) or
           bc:find("emitOutput", 1, true) or
           bc:find("serializeValue", 1, true) or
           bc:find("ipairsFunction", 1, true) or
           bc:find("pairsFunction", 1, true) or
           bc:find("dumperState", 1, true) then
            errorFunction("unable to dump given function", 2)
        end
        return bc
    end
    errorFunction("unable to dump given function", 2)
end
_G.string = string
_G.os = os
os.execute = function() return nil end
os.exit = function() return nil end
os.remove = function() return nil, "disabled" end
os.rename = function() return nil, "disabled" end
_G.coroutine = coroutine
_G.io = nil
_G.debug = exploitFuncs.debug
_G._realSetHook = setHook
_G.utf8 = utf8
_G.next = next
_G.tostring = tostring
_G.tonumber = tonumber
_G.getmetatable = getmetatable
_G.setmetatable = setmetatable
_G.pcall = function(f, ...)
    local results = {pcallFunction(f, ...)}
    local success = results[1]
    if not success then
        local err = results[2]
        if typeFunction(err) == "string" and err:match("TIMEOUT_FORCED_BY_DUMPER") then errorFunction(err) end
    end
    return table.unpack(results)
end
_G.xpcall = function(f, errFunc, ...)
    local function wrapper(err)
        if typeFunction(err) == "string" and err:match("TIMEOUT_FORCED_BY_DUMPER") then return err end
        if errFunc then return errFunc(err) end
        return err
    end
    local results = {xpcallFunction(f, wrapper, ...)}
    local success = results[1]
    if not success then
        local err = results[2]
        if typeFunction(err) == "string" and err:match("TIMEOUT_FORCED_BY_DUMPER") then errorFunction(err) end
    end
    return table.unpack(results)
end
_G.error = errorFunction
if _G.originalError == nil then _G.originalError = errorFunction end
_G.assert = assert
_G.select = select
_G.type = typeFunction
_G.rawget = rawget
_G.rawset = rawset
_G.rawequal = rawEqualFunction
_G.rawlen = rawlen or function(t) return #t end
_G.unpack = table.unpack or unpack
_G.pack = table.pack or function(...) return {n = select("#", ...), ...} end
_G.task = task
_G.wait = wait
_G.Wait = wait
_G.delay = delay
_G.Delay = delay
_G.spawn = spawn
_G.Spawn = spawn
_G.tick = tick
_G.time = time
_G.elapsedTime = elapsedTime
_G.game = game
_G.Game = game
_G.workspace = workspace
_G.Workspace = workspace
_G.script = script
_G.Enum = Enum
_G.Instance = Instance
_G.Random = Random
_G.Vector3 = Vector3
_G.Vector2 = Vector2
_G.CFrame = CFrame
_G.Color3 = Color3
_G.BrickColor = BrickColor
_G.UDim = UDim
_G.UDim2 = UDim2
_G.TweenInfo = TweenInfo
_G.Rect = Rect
_G.Region3 = Region3
_G.Region3int16 = Region3int16
_G.Ray = Ray
_G.NumberRange = NumberRange
_G.NumberSequence = NumberSequence
_G.NumberSequenceKeypoint = NumberSequenceKeypoint
_G.ColorSequence = ColorSequence
_G.ColorSequenceKeypoint = ColorSequenceKeypoint
_G.PhysicalProperties = PhysicalProperties
_G.Font = Font
_G.RaycastParams = RaycastParams
_G.OverlapParams = OverlapParams
_G.PathWaypoint = PathWaypoint
_G.Axes = Axes
_G.Faces = Faces
_G.Vector3int16 = Vector3int16
_G.Vector2int16 = Vector2int16
_G.CatalogSearchParams = CatalogSearchParams
_G.DateTime = DateTime
settings = function()
    local enumKey = "Enum.QualityLevel.Automatic"
    if not _at.enum[enumKey] then
        local p = createProxyObject(enumKey, false)
        dumperState.registry[p] = enumKey
        _at.enum[enumKey] = p
    end
    local qualityProxy = _at.enum[enumKey]
    return {
        Rendering = {QualityLevel = qualityProxy, FrameRateManager = 0, EagerBulkExecution = false},
        Studio    = {},
        Network   = {IncomingReplicationLag = 0},
        Physics   = {PhysicsEnvironmentalThrottle = createProxyObject("Enum.EnviromentalPhysicsThrottle.DefaultAuto", false)},
    }
end
_G.settings = settings
getmetatable = function(x)
    if _at.userdata[x] then return getMetatableFunction(x) end
    if isProxy(x) then return "The metatable is locked" end
    return getMetatableFunction(x)
end
_G.getmetatable = getmetatable
type = function(x)
    if _at.threadLike[x] then return "thread" end
    if _at.userdata[x] then return "userdata" end
    if getProxyValue(x) ~= 0 then return "number" end
    if isProxy(x) then return "userdata" end
    return typeFunction(x)
end
_G.type = type
buffer = {
    create = function(size)
        local b = {}
        _at.buffers[b] = string.rep("\0", size or 0)
        return b
    end,
    fromstring = function(s)
        local b = {}
        _at.buffers[b] = formatValue(s)
        return b
    end,
    tostring = function(b)
        return _at.buffers[b] or ""
    end,
    len = function(b)
        return #(_at.buffers[b] or "")
    end,
    copy = function(dst, dstOffset, src, srcOffset, count)
        local srcData = _at.buffers[src] or ""
        local dstData = _at.buffers[dst] or ""
        srcOffset = (srcOffset or 0) + 1
        dstOffset = (dstOffset or 0) + 1
        local chunk = srcData:sub(srcOffset, count and srcOffset + count - 1 or -1)
        local before = dstData:sub(1, dstOffset - 1)
        local after  = dstData:sub(dstOffset + #chunk)
        _at.buffers[dst] = before .. chunk .. after
    end,
    fill = function(b, offset, value, count)
        local data = _at.buffers[b] or ""
        offset = (offset or 0) + 1
        count  = count or (#data - offset + 1)
        local fill = string.rep(string.char(value % 256), count)
        local before = data:sub(1, offset - 1)
        local after  = data:sub(offset + count)
        _at.buffers[b] = before .. fill .. after
    end,
    writestring = function(b, offset, s, count)
        local data = _at.buffers[b] or ""
        offset = (offset or 0) + 1
        s = formatValue(s)
        if count then s = s:sub(1, count) end
        local before = data:sub(1, offset - 1)
        local after  = data:sub(offset + #s)
        _at.buffers[b] = before .. s .. after
    end,
    readstring = function(b, offset, len)
        local data = _at.buffers[b] or ""
        offset = (offset or 0) + 1
        return data:sub(offset, len and offset + len - 1 or -1)
    end,
    writeu8  = function(b, offset, v) local d=_at.buffers[b] or""; offset=(offset or 0)+1; _at.buffers[b]=d:sub(1,offset-1)..string.char(v%256)..d:sub(offset+1) end,
    readu8   = function(b, offset) local d=_at.buffers[b] or""; return string.byte(d,(offset or 0)+1) or 0 end,
    writeu16 = function(b, offset, v) offset=(offset or 0); buffer.writeu8(b,offset,v%256); buffer.writeu8(b,offset+1,math.floor(v/256)%256) end,
    readu16  = function(b, offset) return buffer.readu8(b,offset) + buffer.readu8(b,(offset or 0)+1)*256 end,
    writeu32 = function(b, offset, v) offset=(offset or 0); for i=0,3 do buffer.writeu8(b,offset+i,math.floor(v/(256^i))%256) end end,
    readu32  = function(b, offset) local v=0; for i=0,3 do v=v+buffer.readu8(b,(offset or 0)+i)*(256^i) end; return v end,
    writei8  = function(b, offset, v) buffer.writeu8(b, offset, v < 0 and v+256 or v) end,
    readi8   = function(b, offset) local v=buffer.readu8(b,offset); return v>=128 and v-256 or v end,
    writei16 = function(b, offset, v) buffer.writeu16(b, offset, v < 0 and v+65536 or v) end,
    readi16  = function(b, offset) local v=buffer.readu16(b,offset); return v>=32768 and v-65536 or v end,
    writei32 = function(b, offset, v) buffer.writeu32(b, offset, v < 0 and v+4294967296 or v) end,
    readi32  = function(b, offset) local v=buffer.readu32(b,offset); return v>=2147483648 and v-4294967296 or v end,
    writef32 = function(b, offset, v) buffer.writeu32(b, offset, math.floor(math.abs(v)*1000)%4294967296) end,
    readf32  = function(b, offset) return buffer.readu32(b,offset)/1000 end,
    writef64 = function(b, offset, v) buffer.writeu32(b, offset, 0); buffer.writeu32(b, (offset or 0)+4, math.floor(math.abs(v)*1000)%4294967296) end,
    readf64  = function(b, offset) return buffer.readu32(b,(offset or 0)+4)/1000 end,
}
_G.buffer = buffer
typeof = function(x)
    if getProxyValue(x) ~= 0 then return "number" end
    if isProxy(x) then
        if _at.typeOverride[x] then return _at.typeOverride[x] end
        local regName = dumperState.registry[x]
        if regName then
            if regName == "Enum" then return "Enums" end
            if regName:match("^Enum%.[^%.]+$") then return "Enum" end
            if regName:match("^Enum%.[^%.]+%.[^%.]+$") then return "EnumItem" end
            if regName:match("Vector3") then return "Vector3" end
            if regName:match("CFrame") then return "CFrame" end
            if regName:match("Color3") then return "Color3" end
            if regName:match("UDim") then return "UDim2" end
        end
        return "Instance"
    end
    if _at.threadLike[x] then return "thread" end
    local mt = getMetatableFunction(x)
    if mt and mt.__typeof then return mt.__typeof end
    return typeFunction(x) == "table" and "table" or typeFunction(x)
end
_G.typeof = typeof
newproxy = function(withMeta)
    local proxy = {}
    _at.userdata[proxy] = true
    if withMeta then
        setmetatable(proxy, {})
    end
    return proxy
end
_G.newproxy = newproxy
tonumber = function(x, base)
    if getProxyValue(x) ~= 0 then return 123456789 end
    return toNumberFunction(x, base)
end
_G.tonumber = tonumber
rawequal = function(a, b) return rawEqualFunction(a, b) end
_G.rawequal = rawequal
tostring = function(x)
    if isProxy(x) then
        local mt = getMetatableFunction(x)
        if mt and mt.__tostring then
            local ok, r = pcallFunction(mt.__tostring, x)
            if ok and r then return r end
        end
        local regName = dumperState.registry[x]
        return regName or "Instance"
    end
    local mt = getMetatableFunction(x)
    if mt and mt.__tostring then
        local ok, r = pcallFunction(mt.__tostring, x)
        if ok and r then return r end
    end
    return toStringFunction(x)
end
_G.tostring = tostring
dumperState.last_http_url = nil
loadstring = function(code, chunkName)
    if typeFunction(code) ~= "string" then return function() return createProxyObject("loaded", false) end end
    local url = dumperState.last_http_url or code
    dumperState.last_http_url = nil
    local libName = nil
    local lowerCode = url:lower()
    local libs = {{pattern = "rayfield", name = "Rayfield"}, {pattern = "orion", name = "OrionLib"}, {pattern = "kavo", name = "Kavo"}, {pattern = "venyx", name = "Venyx"}, {pattern = "sirius", name = "Sirius"}, {pattern = "linoria", name = "Linoria"}, {pattern = "wally", name = "Wally"}, {pattern = "dex", name = "Dex"}, {pattern = "infinite", name = "InfiniteYield"}, {pattern = "hydroxide", name = "Hydroxide"}, {pattern = "simplespy", name = "SimpleSpy"}, {pattern = "remotespy", name = "RemoteSpy"}}
    for _, lib in ipairsFunction(libs) do if lowerCode:find(lib.pattern) then libName = lib.name; break end end
    if libName then
        local proxy = createProxyObject(libName, false)
        dumperState.registry[proxy] = libName
        dumperState.names_used[libName] = true
        if url:match("^https?://") then emitOutput(string.format('local %s = loadstring(game:HttpGet("%s"))()', libName, url)) end
        return function() return proxy end
    end
    if url:match("^https?://") then
        local proxy = createProxyObject("Library", false)
        emitOutput(string.format('local loadstring = loadstring(game:HttpGet("%s"))()', url))
        return function() return proxy end
    end
    if code:match("local%s+a%s*=%s*if%s+true%s+then") then return nil, "attempt to call a nil value" end
    if typeFunction(code) == "string" then code = processString(code) end
    local func, err = loadFunction(code)
    if func then return func end
    local proxy = createProxyObject("LoadedChunk", false)
    return function() return proxy end
end
load = loadstring
_G.loadstring = loadstring
_G.load = loadstring
require = function(module)
    local modName = dumperState.registry[module] or serializeValue(module)
    local proxy = createProxyObject("RequiredModule", false)
    local varName = registerVariable(proxy, "module")
    emitOutput(string.format("local %s = require(%s)", varName, modName))
    return proxy
end
_G.require = require
print = function(...)
    local args = {...}
    local items = {}
    for _, val in ipairsFunction(args) do table.insert(items, serializeValue(val)) end
    emitOutput(string.format("print(%s)", table.concat(items, ", ")))
end
_G.print = print
warn = function(...)
    local args = {...}
    local items = {}
    for _, val in ipairsFunction(args) do table.insert(items, serializeValue(val)) end
    emitOutput(string.format("warn(%s)", table.concat(items, ", ")))
end
_G.warn = warn
-- Tag Roblox-like builtins as C closures so iscclosure() returns true for them
do
    if not _at.cclosureSet then _at.cclosureSet = setmetatable({}, {__mode="k"}) end
    local _cbuiltins = {
        print, warn, tick, time, elapsedTime, pcall, xpcall, error, assert,
        tostring, tonumber, type, typeof, rawget, rawset, rawequal, rawlen,
        setmetatable, getmetatable, ipairs, pairs, next, select, unpack,
        require, loadstring, load,
    }
    for _, fn in ipairs(_cbuiltins) do
        if typeFunction(fn) == "function" then
            _at.cclosureSet[fn] = true
        end
    end
end
_G.shared = shared
local globalBase = _G
local globalMeta = setmetatable({}, {
    __index = function(tbl, key)
        if configuration.VERBOSE then printFunction("[VERBOSE] Accessing field: " .. toStringFunction(key)) end
        local val = rawget(globalBase, key)
        if val == nil then val = rawget(_G, key) end
        if configuration.VERBOSE then
            if val ~= nil then
                if typeFunction(val) == "table" then printFunction("[VERBOSE] Found global table: " .. toStringFunction(key))
                elseif typeFunction(val) == "function" then printFunction("[VERBOSE] Found global function: " .. toStringFunction(key))
                else printFunction("[VERBOSE] Found global value: " .. toStringFunction(key) .. " = " .. toStringFunction(val)) end
            else
                printFunction("[VERBOSE] Missing field, providing dummy function: " .. toStringFunction(key))
                val = function() if configuration.VERBOSE then printFunction("[Missing Function] Called: " .. toStringFunction(key) .. " with 0 arguments") end return nil end
            end
        end
        return val
    end,
    __newindex = function(tbl, key, val) rawset(globalBase, key, val) end
})
_G._G = globalMeta
function proxyTable.reset()
    dumperState = {output = {}, indent = 0, registry = {}, reverse_registry = {}, names_used = {}, parent_map = {}, property_store = {}, call_graph = {}, variable_types = {}, string_refs = {}, proxy_id = 0, callback_depth = 0, pending_iterator = false, last_http_url = nil, last_emitted_line = nil, repetition_count = 0, current_size = 0, limit_reached = false, ls_counter = 0, captured_constants = {}}
    _at.mem = {}
    _at.tags = {}
    _at.sigs = {}
    _at.acts = {}
    _at.json = {}
    _at.enum = {}
    _at.svcCache = {}
    _at.typeOverride = {}
    _at.connState = {}
    _at.pendingHeartbeat = {}
    _at.locEntries = {}
    _at.userdata = {}
    _at.localPlayer = nil
    setmetatable(_at.userdata, {__mode = "k"})
    _at.debugIds = {}
    setmetatable(_at.debugIds, {__mode = "k"})
    _at.debugIdCtr = 0
    uiCounters = {}
    game = createProxyObject("game", true)
    workspace = createProxyObject("workspace", true)
    script = createProxyObject("script", true)
    Enum = createProxyObject("Enum", true)
    shared = createProxyObject("shared", true)
    dumperState.property_store[game] = {PlaceId = numericArg, GameId = numericArg, placeId = numericArg, gameId = numericArg}
    dumperState.property_store[script] = {Name = "DumpedScript", Parent = game, ClassName = "LocalScript"}
    _G.game = game; _G.Game = game; _G.workspace = workspace; _G.Workspace = workspace; _G.script = script; _G.Enum = Enum; _G.shared = shared
    local meta = debugLibrary.getmetatable(Enum)
    meta.__index = function(_, key)
        if key == proxyList or key == "__proxy_id" then return rawget(_, key) end
        local enumName = "Enum." .. formatValue(key)
        if not _at.enum[enumName] then
            local enumProxy = createProxyObject(enumName, false)
            dumperState.registry[enumProxy] = enumName
            _at.enum[enumName] = enumProxy
        end
        return _at.enum[enumName]
    end
    seedCoreRobloxInstances()
    if type(_G._bypassOnReset) == "function" then
        local prevOutput = dumperState.output
        local prevOutputCount = #prevOutput
        local prevIndent = dumperState.indent
        local prevLast = dumperState.last_emitted_line
        local prevRep = dumperState.repetition_count
        local prevSize = dumperState.current_size
        local prevLimit = dumperState.limit_reached
        pcall(_G._bypassOnReset)
        for i = #prevOutput, prevOutputCount + 1, -1 do
            prevOutput[i] = nil
        end
        dumperState.output = prevOutput
        dumperState.indent = prevIndent
        dumperState.last_emitted_line = prevLast
        dumperState.repetition_count = prevRep
        dumperState.current_size = prevSize
        dumperState.limit_reached = prevLimit
    end
end
function proxyTable.get_output() return getFullOutput() end
function proxyTable.save(file) return saveToFile(file) end
function proxyTable.get_call_graph() return dumperState.call_graph end
function proxyTable.get_string_refs() return dumperState.string_refs end
function proxyTable.get_stats() return {total_lines = #dumperState.output, remote_calls = #dumperState.call_graph, suspicious_strings = #dumperState.string_refs, proxies_created = dumperState.proxy_id} end
local dumper = {callId = "LUASPLOIT_", binaryOperatorNames = {["and"] = "AND", ["or"] = "OR", [">"] = "GT", ["<"] = "LT", [">="] = "GE", ["<="] = "LE", ["=="] = "EQ", ["~="] = "NEQ", [".."] = "CAT"}}
function dumper:hook(code) return self.callId .. code end
function dumper:process_expr(expr)
    if not expr then return "nil" end
    if typeFunction(expr) == "string" then return expr end
    local tag = expr.tag or expr.kind
    if tag == "number" or tag == "string" then
        local val = tag == "string" and string.format("%q", expr.text) or (expr.value or expr.text)
        if configuration.CONSTANT_COLLECTION then return string.format("%sGET(%s)", self.callId, val) end
        return val
    end
    if tag == "local" or tag == "global" then return (expr.name or expr.token).text
    elseif tag == "boolean" or tag == "bool" then return toStringFunction(expr.value)
    elseif tag == "binary" then
        local lhs = self:process_expr(expr.lhsoperand)
        local rhs = self:process_expr(expr.rhsoperand)
        local op = expr.operator.text
        local opName = self.binaryOperatorNames[op]
        if opName then return string.format("%s%s(%s, %s)", self.callId, opName, lhs, rhs) end
        return string.format("(%s %s %s)", lhs, op, rhs)
    elseif tag == "call" then
        local func = self:process_expr(expr.func)
        local args = {}
        for i, node in ipairsFunction(expr.arguments) do args[i] = self:process_expr(node.node or node) end
        return string.format("%sCALL(%s, %s)", self.callId, func, table.concat(args, ", "))
    elseif tag == "indexname" or tag == "index" then
        local exprStr = self:process_expr(expr.expression)
        local keyStr = tag == "indexname" and string.format("%q", expr.index.text) or self:process_expr(expr.index)
        return string.format("%sCHECKINDEX(%s, %s)", self.callId, exprStr, keyStr)
    end
    return "nil"
end
function dumper:process_statement(stmt)
    if not stmt then return "" end
    local tag = stmt.tag
    if tag == "local" or tag == "assign" then
        local vars, vals = {}, {}
        for _, node in ipairsFunction(stmt.variables or {}) do table.insert(vars, self:process_expr(node.node or node)) end
        for _, node in ipairsFunction(stmt.values or {}) do table.insert(vals, self:process_expr(node.node or node)) end
        return (tag == "local" and "local " or "") .. table.concat(vars, ", ") .. " = " .. table.concat(vals, ", ")
    elseif tag == "block" then
        local stmts = {}
        for _, s in ipairsFunction(stmt.statements or {}) do table.insert(stmts, self:process_statement(s)) end
        return table.concat(stmts, "; ")
    end
    return self:process_expr(stmt) or ""
end
local function _loosePasteCode(code)
    if typeFunction(code) ~= "string" then return code end
    code = code:gsub("```lua", ""):gsub("```", "")
    return code
end
local function _loadLooseChunk(code, chunkName)
    local sanitized = processString(_loosePasteCode(code))
    local lines = {}
    sanitized:gsub("([^\n]*)\n?", function(line)
        if line ~= "" or #lines == 0 or sanitized:sub(-1) == "\n" then table.insert(lines, line) end
    end)
    local skipped = {}
    for _ = 1, 400 do
        local current = table.concat(lines, "\n")
        local func, err = loadFunction(current, chunkName)
        if func then return func, nil, current, skipped end
        local lineNo = toNumberFunction(toStringFunction(err):match("%]:(%d+):") or toStringFunction(err):match(":(%d+):"))
        if not lineNo or not lines[lineNo] or skipped[lineNo] then return nil, err, current, skipped end
        skipped[lineNo] = lines[lineNo]
        lines[lineNo] = "-- " .. lines[lineNo]
    end
    return nil, "too many invalid loose-paste lines", table.concat(lines, "\n"), skipped
end
function proxyTable.dump_file(inputPath, outputPath)
    proxyTable.reset()
    local file = ioLibrary.open(inputPath, "rb")
    if not file then
    printFunction("error: cannot open input")
        return false
    end
    local code = file:read("*a")
    file:close()
    printFunction("input: normalize")
    local func, err, sanitized, skipped = _loadLooseChunk(code, "Obfuscated_Script")
    if not func then
        printFunction("error: load " .. toStringFunction(err))
        return false
    end
    if skipped then
        local skippedCount = 0
        for _ in pairsFunction(skipped) do skippedCount = skippedCount + 1 end
        if skippedCount > 0 then printFunction("input: skipped-lines=" .. toStringFunction(skippedCount)) end
    end
    local _SANDBOX_BLOCK = {
        io=true, os=true, debug=true, dofile=true, loadfile=true,
        require=true, package=true, socket=true, ffi=true,
        collectgarbage=true,
    }
    local _rawTb = debugLibrary and debugLibrary.traceback
    local _badTbWords = {
        "sandbox","hook","intercept","mock","proxy","virtual_env",
        "decompil","emulat","simulat","fake_","getupval","hookfunc",
        "replaceclos","newcclos","restorefunction","bypass","dumper",
    }
    local _tbWrapper = function(thread, msg, level)
        local ok, tb
        if _rawTb then
            if typeFunction(thread) == "thread" then
                ok, tb = pcallFunction(_rawTb, thread, msg, level)
            else
                ok, tb = pcallFunction(_rawTb, thread, msg)
            end
        end
        if not ok or typeFunction(tb) ~= "string" then
            return "stack traceback:\nt[RobloxGameScript]: in function <RobloxGameScript:1>"
        end
        local lines = {}
        for line in (tb .. "\n"):gmatch("([^\n]*)\n") do
            local lo = line:lower()
            local bad = false
            for _, w in next, _badTbWords do
                if lo:find(w, 1, true) then bad = true; break end
            end
            if not bad then lines[#lines + 1] = line end
        end
        local cleaned = table.concat(lines, "\n")
        cleaned = cleaned:gsub("%[([%w%+%/]+)%]", function(inner)
            if #inner + 2 < 10 then return "[RobloxGameScript]" end
            return "[" .. inner .. "]"
        end)
        if #cleaned < 20 then
            return "stack traceback:\nt[RobloxGameScript]: in function <RobloxGameScript:1>"
        end
        return cleaned
    end
    local _SAFE_DEBUG = {
        getinfo = function(func, ...)
            if typeFunction(func) == "number" then
                return nil
            end
            return {source = "=[C]", what = "C", name = "C function", short_src = "[C]"}
        end,
        traceback  = _tbWrapper,
        getupvalue = function(fn, i) return nil end,
    }
    local _SAFE_OS = {
        clock = function() local _bc=rawget(_G,"_bypassClock"); return _bc and _bc() or osLibrary.clock() end,
        time  = osLibrary.time,
        date  = osLibrary.date,
    }
    local env = setmetatable({
        _VERSION = "Luau",
        LuraphContinue = nil,
        __LC__ = function() end,
        script = script, game = game, workspace = workspace,
        io      = nil,
        os      = _SAFE_OS,
        debug   = _SAFE_DEBUG,
        error   = _origError,
        dofile  = nil,
        loadfile = nil,
        require = nil,
        package = nil,
        socket  = nil,
        ffi     = nil,
        collectgarbage = nil,
        newproxy = newproxy,
        -- hide _G metatable from scripts
        getmetatable = function(obj)
            if obj == _G or obj == env then return nil end
            if _at.userdata[obj] then return getMetatableFunction(obj) end
            if isProxy(obj) then return "The metatable is locked" end
            return getMetatableFunction(obj)
        end,
        LUASPLOIT_CHECKINDEX = function(tbl, key)
            local val = tbl[key]
            if typeFunction(val) == "table" and not dumperState.registry[val] then
                dumperState.ls_counter = dumperState.ls_counter + 1
                dumperState.registry[val] = "v" .. dumperState.ls_counter
            end
            return val
        end,
        LUASPLOIT_GET = function(v) return v end,
        LS_CALL = function(f, ...)
            if typeFunction(f) ~= "function" then return nil end
            return f(...)
        end,
        LS_NAMECALL = function(t, method, ...)
            if typeFunction(t) ~= "table" then return nil end
            if typeFunction(t[method]) ~= "function" then return nil end
            return t[method](t, ...)
        end,
        LUASPLOIT_CALL = function(f, ...) return f(...) end,
        LUASPLOIT_NAMECALL = function(t, method, ...) return t[method](t, ...) end,
        pcall = function(f, ...)
            local override = rawget(_G, "_bypassPcall")
            if typeFunction(override) == "function" then
                local res = {override(pcallFunction, f, ...)}
                if not res[1] and toStringFunction(res[2]):match("TIMEOUT") then errorFunction(res[2], 0) end
                return unpack(res)
            end
            local res = {pcallFunction(f, ...)}
            if not res[1] and toStringFunction(res[2]):match("TIMEOUT") then errorFunction(res[2], 0) end
            return unpack(res)
        end
    }, {
        __index = function(_, k)
            if _SANDBOX_BLOCK[k] then return nil end
            -- block dumper internal globals from leaking into script env
            if k == "LuraphContinue" or k == "__FLAMEDUMPER_REQUIRE_ONLY"
            or k == "proxyTable" or k == "dumperState" or k == "_at" then
                return nil
            end
            return _G[k]
        end,
        __newindex = _G
    })
    do
        local _applied = false
        if debugLibrary and debugLibrary.getupvalue and debugLibrary.setupvalue then
            for _i = 1, 256 do
                local _n = debugLibrary.getupvalue(func, _i)
                if not _n then break end
                if _n == "_ENV" then
                    debugLibrary.setupvalue(func, _i, env)
                    _applied = true
                    break
                end
            end
        end
        if not _applied and type(setfenv) == "function" then
            local _si = debugLibrary and debugLibrary.getinfo and debugLibrary.getinfo(setfenv, "S")
            if _si and _si.what == "C" then setfenv(func, env) end
        end
    end
    printFunction("vm: running")
    local startClock = osLibrary.clock()
    setHook(function()
        if osLibrary.clock() - startClock > configuration.TIMEOUT_SECONDS then
            errorFunction("TIMEOUT", 0)
        end
    end, "", 1000)
    local success, runErr = xpcallFunction(function() func() end, function(e) return toStringFunction(e) end)
    setHook()
    if not success and not toStringFunction(runErr):match("TIMEOUT") then
        emitComment("Runtime: " .. toStringFunction(runErr))
    end
    local saved = proxyTable.save(outputPath or configuration.OUTPUT_FILE)
    if saved then
        local stats = proxyTable.get_stats()
        printFunction(string.format("done: lines=%d remotes=%d strings=%d",
            stats.total_lines, stats.remote_calls, stats.suspicious_strings))
    else
        printFunction("error: write failed")
    end
    return saved
end
function proxyTable.dump_string(code, outputPath)
    proxyTable.reset()
    if code then code = processString(code) end
    local func, err = loadFunction(code)
    if not func then
        emitComment("Load Error: " .. (err or "unknown"))
        if outputPath then proxyTable.save(outputPath) end
        return false, err
    end
    local _DS_BLOCK = {
        io=true, os=true, dofile=true, loadfile=true,
        require=true, package=true, socket=true, ffi=true,
        collectgarbage=true, debug=true,
    }
    local _DS_OS = { clock=function() local _bc=rawget(_G,"_bypassClock"); return _bc and _bc() or osLibrary.clock() end, time=osLibrary.time, date=osLibrary.date }
    local dsEnv = setmetatable({
        _VERSION="Luau",
        io=nil, os=_DS_OS, debug=nil, dofile=nil, loadfile=nil,
        require=nil, package=nil, socket=nil, ffi=nil,
        collectgarbage=nil, newproxy=newproxy,
        pcall = function(f, ...)
            local override = rawget(_G, "_bypassPcall")
            if typeFunction(override) == "function" then
                local res = {override(pcallFunction, f, ...)}
                if not res[1] and toStringFunction(res[2]):match("TIMEOUT") then errorFunction(res[2], 0) end
                return unpack(res)
            end
            local res = {pcallFunction(f, ...)}
            if not res[1] and toStringFunction(res[2]):match("TIMEOUT") then errorFunction(res[2], 0) end
            return unpack(res)
        end,
    }, {
        __index = function(_, k)
            if _DS_BLOCK[k] then return nil end
            return _G[k]
        end,
        __newindex = _G,
    })
    do
        local _applied = false
        if debugLibrary and debugLibrary.getupvalue and debugLibrary.setupvalue then
            for _i = 1, 256 do
                local _n = debugLibrary.getupvalue(func, _i)
                if not _n then break end
                if _n == "_ENV" then
                    debugLibrary.setupvalue(func, _i, dsEnv)
                    _applied = true
                    break
                end
            end
        end
        if not _applied and type(setfenv) == "function" then
            local _si = debugLibrary and debugLibrary.getinfo and debugLibrary.getinfo(setfenv, "S")
            if _si and _si.what == "C" then setfenv(func, dsEnv) end
        end
    end
    local startClock = osLibrary.clock()
    setHook(function()
        if osLibrary.clock() - startClock > configuration.TIMEOUT_SECONDS then
            errorFunction("TIMEOUT", 0)
        end
    end, "", 1000)
    xpcallFunction(function() func() end, function(e)
        emitComment("Runtime: " .. toStringFunction(e))
    end)
    setHook()
    if outputPath then return proxyTable.save(outputPath) end
    return true, getFullOutput()
end
do
    local bypassPath = (arg and arg[0] and arg[0]:match("^(.+[/])")) or ""
    local ok, err = pcall(dofile, bypassPath .. "bypass.lua")
    if not ok then
        local ok2 = pcall(dofile, "bypass.lua")
        if not ok2 then
            printFunction("[dumper] bypass.lua not found, continuing without supplement")
        end
    end
end

_G.LuraphContinue = nil
if not rawget(_G, "__FLAMEDUMPER_REQUIRE_ONLY") then
    if arg and arg[1] then
        local success = proxyTable.dump_file(arg[1], arg[2])
        if success then end
    else
        local file = ioLibrary.open("obfuscated.lua", "rb")
        if file then
            file:close()
            local success = proxyTable.dump_file("obfuscated.lua")
            if success then
                printFunction(proxyTable.get_output())
            end
        else
            printFunction("Usage: lua dumper.lua <input> [output] [key]")
        end
    end
end
return proxyTable
