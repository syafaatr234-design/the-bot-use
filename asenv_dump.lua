local a = debug
local b = debug.sethook
local c = debug.getinfo
local d = debug.traceback
local e = load
local f = loadstring or load
local g = pcall
local h = xpcall
local i = error
local j = type
local k = getmetatable
local l = rawequal
local m = tostring
local n = tonumber
local o = io
local p = os
local q = {}
-- ANTI-DETECTION BYPASS
local _old_enum = Enum
Enum = setmetatable({}, {
    __index = function(t, k)
        if k == "GetEnums" then
            return function(self)
                local enums = {}
                for k2, v2 in pairs(self) do
                    if type(k2) == "string" and type(v2) ~= "function" and k2 ~= "GetEnums" then
                        table.insert(enums, v2)
                    end
                end
                return enums
            end
        end
        return _old_enum[k]
    end
})
q.__index = q

local r, BLOCKED_OUTPUT_PATTERNS = (function()
local r = {
    MAX_DEPTH = 50,
    MAX_TABLE_ITEMS = 10000,
    OUTPUT_FILE = "dumped_output.lua",
    VERBOSE = false,
    TRACE_CALLBACKS = true,
    TIMEOUT_SECONDS = 120,
    MAX_REPEATED_LINES = 200,
    MIN_DEOBF_LENGTH = 50,
    MAX_OUTPUT_SIZE = 200 * 1024 * 1024,
    CONSTANT_COLLECTION = true,
    INSTRUMENT_LOGIC = true,
    DUMP_GLOBALS = true,
    DUMP_ALL_STRINGS = false,
    DUMP_WAD_STRINGS = false,
    DUMP_DECODED_STRINGS = false,
    DUMP_LIGHTCATE_STRINGS = false,
    EMIT_XOR = false,
    DUMP_UPVALUES = true,
    MAX_UPVALUES_PER_FUNCTION = 200,
    DUMP_GC_SCAN = true,
    DUMP_INSTANCE_CREATIONS = true,
    DUMP_SCRIPT_LOADS = true,
    DUMP_REMOTE_SUMMARY = true,
    MAX_GC_OBJECTS = 500,
    MAX_GC_SCAN_FUNCTIONS = 500,
    MAX_INSTANCE_CREATIONS = 1000,
    MAX_SCRIPT_LOADS = 200,
    MAX_SCRIPT_LOAD_SNIPPET = 80,
    DUMP_FUNCTIONS = true,
    DUMP_METATABLES = true,
    DUMP_CLOSURES = true,
    DUMP_REMOTE_CALLS = true,
    DUMP_CONSTANTS = true,
    DUMP_HOOKS = true,
    DUMP_SIGNALS = true,
    DUMP_ATTRIBUTES = true,
    DUMP_PROPERTIES = true,
    TRACK_ENV_WRITES = true,
    TRACK_ENV_READS = false,
    COLLECT_ALL_CALLS = true,
    EMIT_COMMENTS = true,
    STRIP_WHITESPACE = false,
    MAX_STRING_LENGTH = 65536,
    MAX_PROXY_DEPTH = 32,
    MAX_HOOK_CALLS = 500,
    MAX_REMOTE_CALLS = 1000,
    MAX_SIGNAL_CALLBACKS = 100,
    MAX_CLOSURE_REFS = 500,
    MAX_CONST_PER_FUNCTION = 512,
    MAX_DEFERRED_HOOKS = 200,
    OBFUSCATION_THRESHOLD = 0.35,
    INLINE_SMALL_FUNCTIONS = true,
    EMIT_LOOP_COUNTER = false,
    EMIT_CALL_GRAPH = true,
    EMIT_STRING_REFS = true,
    EMIT_TYPE_ANNOTATIONS = false,
    LOOP_DETECT_THRESHOLD = 100,
    ENVLOGGER_RUN_SUMMARY = false,
    ENVLOGGER_INTERN_POOLS = false,
    ENVLOGGER_DIAGNOSTICS = false,
    MAX_LINES_PER_SECTION = 10000,
    ENVLOGGER_LABEL_GLOBAL_SOURCE = false,
    DUMP_PROPERTY_STORE = true,
    DUMP_HOOK_CALLS = true,
    DUMP_LOOP_SUMMARY = true,
    DUMP_COUNTERS = true,
    DUMP_RUNTIME_POINTERS = true,
    DUMP_OBFUSCATOR_FINGERPRINT = true,
    DUMP_THREAT_ASSESSMENT = true,
    DUMP_TIMELINE = true,
    LOOP_SUMMARY_TOP_N = 25,
    THREAT_SAMPLE_CAP = 20,
    THREAT_SCAN_GLOBAL_TABLE = true,
    TIMELINE_CAP = 200,
}
local BLOCKED_OUTPUT_PATTERNS = {
    "os%.execute",
    "os%.getenv",
    "os%.exit",
    "os%.remove",
    "os%.rename",
    "os%.tmpname",
    "io%.open",
    "io%.popen",
    "io%.lines",
    "io%.read",
    "io%.write",
    "total %d",
    "^drwx", "^%-rwx",
    "^[dD]irectory of ",
    "[Vv]olume in drive",
    "/etc/",
    "/home/",
    "/root/",
    "/var/",
    "/tmp/",
    "/proc/",
    "/sys/",
    "C:\\[Uu]sers\\",
    "C:\\[Ww]indows\\",
    "C:\\[Pp]rogram",
    "PATH=",
    "HOME=",
    "USER=",
    "SHELL=",
    "TOKEN%s*=",
    "SECRET%s*=",
    "PASSWORD%s*=",
    "API_KEY%s*=",
    "WEBHOOK%s*=",
    "Nz[A-Za-z0-9_%-]+%.[A-Za-z0-9_%-]+%.[A-Za-z0-9_%-]+",
    "discord%.com/api/webhooks/",
    "discordapp%.com/api/webhooks/",
    "ghp_[A-Za-z0-9]+",
    "gho_[A-Za-z0-9]+",
    "ghs_[A-Za-z0-9]+",
}
return r, BLOCKED_OUTPUT_PATTERNS
end)()

local s = arg and arg[3]
if s then
    print("[Dumper] Auto-Input Key Detected: " .. tostring(s))
end
local t = {
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
    lar_counter = 0,
    -- RemoteEvent BP
    remote_events = {},
    remote_functions = {},
    remote_callbacks = {},
    -- Tools BP
    tools = {},
    equipped_tool = nil,
    tool_actions = {},
    -- DLL BP
    dlls = {},
    dll_exports = {},
    dll_calls = {},
    -- Instance Visibility BP
    instance_visibility = {},
    hidden_instances = {},
    -- Explorer BP
    explorer_data = {},
    instance_tree = {},
}

local _fflags = {}
local _fflags_defaults = {
    StepMaxWorld = "30", WorldStepMax = "30", AngularVelociryLimit = "360",
    MaxTimestepMultiplierAcceleration = "2147483647", MaxTimestepMultiplierBuoyancy = "2147483647",
    MaxTimestepMultiplierContstraint = "2147483647", MaxDataPacketPerSend = "2147483647",
    ServerMaxBandwith = "52", PhysicsSenderMaxBandwidthBps = "20000", S2PhysicsSenderRate = "15000",
    MaxMissedWorldStepsRemembered = "-2147483648", LargeReplicatorEnabled9 = "true",
    LargeReplicatorWrite5 = "true", LargeReplicatorRead5 = "true", LargeReplicatorSerializeRead3 = "true",
    LargeReplicatorSerializeWrite4 = "true", NextGenReplicatorEnabledWrite4 = "true",
    GameNetPVHeaderLinearVelocityZeroCutoffExponent = "-5000",
    GameNetPVHeaderRotationalVelocityZeroCutoffExponent = "-5000",
    CheckPVDifferencesForInterpolationMinVelThresholdStudsPerSecHundredth = "1",
    CheckPVDifferencesForInterpolationMinRotVelThresholdRadsPerSecHundredth = "1",
    CheckPVCachedVelThresholdPercent = "10", CheckPVCachedRotVelThresholdPercent = "10",
    CheckPVLinearVelocityIntegrateVsDeltaPositionThresholdPercent = "1",
    InterpolationFramePositionThresholdMillionth = "5", InterpolationFrameVelocityThresholdMillionth = "5",
    InterpolationFrameRotVelocityThresholdMillionth = "5",
    TimestepArbiterVelocityCriteriaThresholdTwoDt = "2147483646",
    TimestepArbiterHumanoidLinearVelThreshold = "1", TimestepArbiterHumanoidTurningVelThreshold = "1",
    TimestepArbiterOmegaThou = "1073741823", SimExplicitlyCappedTimestepMultiplier = "2147483646",
    StreamJobNOUVolumeCap = "2147483647", StreamJobNOUVolumeLengthCap = "2147483647",
    ReplicationFocusNouExtentsSizeCutoffForPauseStuds = "2147483647",
    SimOwnedNOUCountThresholdMillionth = "2147483647", GameNetDontSendRedundantDeltaPositionMillionth = "1",
    GameNetDontSendRedundantNumTimes = "1", MaxAcceptableUpdateDelay = "1",
    DebugSendDistInSteps = "-2147483648", DisableDPIScale = "true"
}

local s = arg[3] or "NoKey"
local u = tonumber(arg[4]) or tonumber(arg[3]) or 123456789
local v = {}
local function w(x)
    if j(x) ~= "table" then
        return false
    end
    local y, z =
        pcall(
        function()
            return rawget(x, v) == true
        end
    )
    return y and z
end
local function A(x)
    if j(x) == "number" then
        return x
    end
    if w(x) then
        return rawget(x, "__value") or 0
    end
    return 0
end
local e = loadstring or load
local B = print
local C = warn or function() end
local D = pairs
local E = ipairs
local j = type
local m = tostring
local F = {}
local function G(x)
    if j(x) ~= "table" then
        return false
    end
    local y, z =
        pcall(
        function()
            return rawget(x, F) == true
        end
    )
    return y and z
end
local function H(x)
    if not G(x) then
        return nil
    end
    return rawget(x, "__proxy_id")
end
local function I(J)
    if j(J) ~= "string" then
        return '"'
    end
    local K = {}
    local L, M = 1, #J
    local function N(O)
        return O:gsub(
            "\\\\(.)",
            function(P)
                if P:match('[abfnrtv\\\\%\'%\\"%[%]0-9xu]') then
                    return "" .. P
                end
                return P
            end
        )
    end
    local function Q(R)
        if not R or R == '"' then
            return ""
        end
        R =
            R:gsub(
            "0[bB]([01_]+)",
            function(S)
                local T = S:gsub("_", "")
                local U = n(T, 2)
                return U and m(U) or "0"
            end
        )
        R =
            R:gsub(
            "0[xX]([%x_]+)",
            function(S)
                local T = S:gsub("_", '"')
                return "0x" .. T
            end
        )
        while R:match("%d_+%d") do
            R = R:gsub("(%d)_+(%d)", "%1%2")
        end
        local V = {{"+=", "+"}, {"-=", "-"}, {"*=", "*"}, {"/=", "/"}, {"%%=", "%%"}, {"%^=", "^"}, {"%.%.=", ".."}}
        for W, X in ipairs(V) do
            local Y, Z = X[1], X[2]
            R =
                R:gsub(
                "([%a_][%w_]*)%s*" .. Y,
                function(_)
                    return _ .. " = " .. _ .. " " .. Z .. " "
                end
            )
            R =
                R:gsub(
                "([%a_][%w_]*%.[%a_][%w_%.]+)%s*" .. Y,
                function(_)
                    return _ .. " = " .. _ .. " " .. Z .. " "
                end
            )
            R =
                R:gsub(
                "([%a_][%w_]*%b[])%s*" .. Y,
                function(_)
                    return _ .. " = " .. _ .. " " .. Z .. " "
                end
            )
        end
        R = R:gsub("([^%w_])continue([^%w_])", "%1_G.LuraphContinue()%2")
        R = R:gsub("^continue([^%w_])", "_G.LuraphContinue()%1")
        R = R:gsub("([^%w_])continue$", "%1_G.LuraphContinue()")
        return R
    end
    local function a0(a1)
        local a2 = 0
        while a1 <= M and J:byte(a1) == 61 do
            a2 = a2 + 1
            a1 = a1 + 1
        end
        return a2, a1
    end
    local function a3(a4, a5)
        local a6 = "]" .. string.rep("=", a5) .. "]"
        local a7, a8 = J:find(a6, a4, true)
        return a8 or M
    end
    local a9 = 1
    while L <= M do
        local aa = J:byte(L)
        if aa == 91 then
            local a5, ab = a0(L + 1)
            if ab <= M and J:byte(ab) == 91 then
                table.insert(K, Q(J:sub(a9, L - 1)))
                local ac = L
                local ad = a3(ab + 1, a5)
                table.insert(K, J:sub(ac, ad))
                L = ad
                a9 = L + 1
            end
        elseif aa == 45 and L + 1 <= M and J:byte(L + 1) == 45 then
            table.insert(K, Q(J:sub(a9, L - 1)))
            local ae = L
            if L + 2 <= M and J:byte(L + 2) == 91 then
                local a5, ab = a0(L + 3)
                if ab <= M and J:byte(ab) == 91 then
                    local ad = a3(ab + 1, a5)
                    table.insert(K, J:sub(ae, ad))
                    L = ad
                    a9 = L + 1
                    L = L + 1
                end
            end
            local af = J:find("\n", L + 2, true)
            if af then
                L = af
            else
                L = M
            end
            table.insert(K, J:sub(ae, L))
            a9 = L + 1
        elseif aa == 34 or aa == 39 or aa == 96 then
            table.insert(K, Q(J:sub(a9, L - 1)))
            local ag = aa
            local ac = L
            L = L + 1
            while L <= M do
                local ah = J:byte(L)
                if ah == 92 then
                    L = L + 1
                elseif ah == ag then
                    break
                end
                L = L + 1
            end
            local ai = J:sub(ac + 1, L - 1)
            ai = N(ai)
            if ag == 96 then
                table.insert(K, '"' .. ai:gsub('"', '\\\\"') .. '"')
            else
                local aj = string.char(ag)
                table.insert(K, aj .. ai .. aj)
            end
            a9 = L + 1
        end
        L = L + 1
    end
    table.insert(K, Q(J:sub(a9)))
    return table.concat(K)
end
local function ak(al, am)
    local R, an = e(al, am)
    if R then
        return R
    end
    B("\n[CRITICAL ERROR] Failed to load script!")
    B("[LUA_LOAD_FAIL] " .. m(an))
    local ao = tonumber(an:match(":(%d+):"))
    local ap = an:match("near '([^']+)'")
    if ap then
        local a1 = al:find(ap, 1, true)
        if a1 then
            local aq = math.max(1, a1 - 50)
            local ar = math.min(#al, a1 + 50)
            B("Context around error:")
            B("..." .. al:sub(aq, ar) .. "...")
        end
    end
    local as = o.open("DEBUG_FAILED_TRANSPILE.lua", "w")
    if as then
        as:write(al)
        as:close()
        B("[*] Saved to 'DEBUG_FAILED_TRANSPILE.lua' for inspection")
    end
    return nil, an
end
local function at(O, au)
    if t.limit_reached then
        return
    end
    if O == nil then
        return
    end
    local av = au and "" or string.rep("    ", t.indent)
    local aw = av .. m(O)
    local ax = #aw + 1
    if t.current_size + ax > r.MAX_OUTPUT_SIZE then
        t.limit_reached = true
        local ay = "-- [CRITICAL] Dump stopped: File size exceeded 6MB limit."
        table.insert(t.output, ay)
        t.current_size = t.current_size + #ay
        error("DUMP_LIMIT_EXCEEDED")
    end
    if aw == t.last_emitted_line then
        t.repetition_count = t.repetition_count + 1
        if t.repetition_count <= r.MAX_REPEATED_LINES then
            table.insert(t.output, aw)
            t.current_size = t.current_size + ax
        elseif t.repetition_count == r.MAX_REPEATED_LINES + 1 then
            local ay = av .. "-- [Repeated lines suppressed...]"
            table.insert(t.output, ay)
            t.current_size = t.current_size + #ay
        end
    else
        t.last_emitted_line = aw
        t.repetition_count = 0
        table.insert(t.output, aw)
        t.current_size = t.current_size + ax
    end
    if r.VERBOSE and t.repetition_count <= 1 then
        B(aw)
    end
end
local function az(O)
    at("-- " .. m(O or ""))
end
local function aA()
    t.last_emitted_line = nil
    table.insert(t.output, "")
end
local function aB()
    return table.concat(t.output, "\n")
end
local function aC(aD)
    local as = o.open(aD or r.OUTPUT_FILE, "w")
    if as then
        as:write(aB())
        as:close()
        return true
    end
    return false
end
local function aE(aF)
    if aF == nil then
        return "nil"
    end
    if j(aF) == "string" then
        return aF
    end
    if j(aF) == "number" or j(aF) == "boolean" then
        return m(aF)
    end
    if j(aF) == "table" then
        if t.registry[aF] then
            return t.registry[aF]
        end
        if G(aF) then
            local aG = H(aF)
            return aG and "proxy_" .. aG or "proxy"
        end
    end
    local y, O = pcall(m, aF)
    return y and O or "unknown"
end
local function aH(aF)
    local O = aE(aF)
    local aI =
        O:gsub("\\\\", "\\\\\\\\"):gsub('"', '\\\\"'):gsub("\n", "\n"):gsub("\\r", "\\\\r"):gsub("\\t", "\\\\t")
    return '"' .. aI .. '"'
end
local aJ = {
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
    ContentProvider = "ContentProvider",
    Debris = "Debris",
    ReplicatedFirst = "ReplicatedFirst",
    LocalizationService = "LocalizationService",
    MaterialService = "MaterialService",
    Selection = "Selection",
    ScriptContext = "ScriptContext",
    TestService = "TestService",
    LogService = "LogService",
    PluginManager = "PluginManager",
    ScriptEditorService = "ScriptEditorService",
    StudioService = "StudioService",
    ChangeHistoryService = "ChangeHistoryService",
    Mouse = "Mouse",
    KeyframeSequenceProvider = "KeyframeSequenceProvider",
    AnimationService = "AnimationService",
    BadgeService = "BadgeService",
    VoiceChatService = "VoiceChatService",
    PrivateMessagingService = "PrivateMessagingService",
    FriendMessengerService = "FriendMessengerService",
    NotificationService = "NotificationService",
    PolicyService = "PolicyService",
    StatsService = "StatsService",
    PerformanceService = "PerformanceService",
    MemoryStoreService = "MemoryStoreService",
    SocialService = "SocialService",
    NetworkSettings = "NetworkSettings",
    TouchEnabledService = "TouchEnabledService",
    GameSettings = "GameSettings",
    FocusService = "FocusService",
    UserGameSettings = "UserGameSettings",
    UtilityService = "UtilityService",
    WebService = "WebService",
    BasePlayerSettings = "BasePlayerSettings",
    ControllerService = "ControllerService",
    DragDetectorService = "DragDetectorService",
    FastFlags = "FastFlags",
    FlagService = "FlagService",
    FrameRateManager = "FrameRateManager",
    GamepadService = "GamepadService",
    GeometryService = "GeometryService",
    GestureService = "GestureService",
    IconService = "IconService",
    InputService = "InputService",
    LiveOpsService = "LiveOpsService",
    MultiModalService = "MultiModalService",
    NavigationService = "NavigationService",
    ParticleEmitterService = "ParticleEmitterService",
    PointsService = "PointsService",
    PresenceService = "PresenceService",
    PurchasePromptService = "PurchasePromptService",
    ReportageService = "ReportageService",
    ScreenshotService = "ScreenshotService",
    ScreenShotService = "ScreenShotService",
    SecureMessagingService = "SecureMessagingService",
    ServerReplicatorService = "ServerReplicatorService",
    ShaderService = "ShaderService",
    SkyboxService = "SkyboxService",
    SmokeService = "SmokeService",
    StickerService = "StickerService",
    StreamableService = "StreamableService",
    TelemetryService = "TelemetryService",
    TerrainService = "TerrainService",
    TestHarnessService = "TestHarnessService",
    TestServiceLegacy = "TestServiceLegacy",
    TextureService = "TextureService",
    ToolService = "ToolService",
    TutorialService = "TutorialService",
    UserService = "UserService",
    ValueService = "ValueService",
    WeaveService = "WeaveService",
    WebGLService = "WebGLService",
    WebRequestService = "WebRequestService",
    WindowService = "WindowService",
    VirtualUser = "VirtualUser",
    AssetService = "AssetService",
    AnalyticsService = "AnalyticsService",
    GroupService = "GroupService",
    FriendsService = "FriendsService",
    AccountInformationService = "AccountInformationService",
    AdService = "AdService",
    AdvancedDraggerService = "AdvancedDraggerService",
    AssetManagerService = "AssetManagerService",
    AssetThemeService = "AssetThemeService",
    AudioAnalyzerService = "AudioAnalyzerService",
    AudioService = "AudioService",
    AvatarExportService = "AvatarExportService",
    AvatarService = "AvatarService",
    BaseScriptService = "BaseScriptService",
    BasicSettings = "BasicSettings",
    BinaryDataService = "BinaryDataService",
    BodyMoverService = "BodyMoverService",
    BrowserService = "BrowserService",
    CSGDictionaryService = "CSGDictionaryService",
    CSGPersistenceService = "CSGPersistenceService",
    CSGPolygonService = "CSGPolygonService",
    CSGService = "CSGService",
    CSGSurfaceService = "CSGSurfaceService",
    CSGToolService = "CSGToolService",
    CSGValidationService = "CSGValidationService",
    CachingService = "CachingService",
    CameraScriptService = "CameraScriptService",
    CameraService = "CameraService",
    CaptchaService = "CaptchaService",
    ClickDetectorService = "ClickDetectorService",
    CloudService = "CloudService",
    ClusterService = "ClusterService",
    CommandService = "CommandService",
    CommerceService = "CommerceService",
    ConnectorService = "ConnectorService",
    ConstraintService = "ConstraintService",
    CraftService = "CraftService",
    CreatorService = "CreatorService",
    CrossDataService = "CrossDataService",
    CuratedContentService = "CuratedContentService",
    CustomEventService = "CustomEventService",
    CustomMeshService = "CustomMeshService",
    DataModel = "DataModel",
    DialogService = "DialogService",
    DisplayOrderService = "DisplayOrderService",
    DistributeService = "DistributeService",
    EmoteService = "EmoteService",
    EncoderService = "EncoderService",
    EngineService = "EngineService",
    ExperienceInviteService = "ExperienceInviteService",
    FaceAnimatorService = "FaceAnimatorService",
    FilePickerService = "FilePickerService",
    FileService = "FileService",
    ForceFeedbackService = "ForceFeedbackService",
    GamepassService = "GamepassService",
    GearService = "GearService",
    GravityService = "GravityService",
    GridService = "GridService",
    HighlightService = "HighlightService",
    HomeService = "HomeService",
    IdentityService = "IdentityService",
    ImageService = "ImageService",
    ImportService = "ImportService",
    InternalService = "InternalService",
    JobService = "JobService",
    KeyboardService = "KeyboardService",
    LMSController = "LMSController",
    LMSService = "LMSService",
    LODService = "LODService",
    LSPersistenceService = "LSPersistenceService",
    LeaderStatsService = "LeaderStatsService",
    LensService = "LensService",
    LevelOfDetailService = "LevelOfDetailService",
    LibraryService = "LibraryService",
    LightService = "LightService",
    LightingService = "LightingService",
    LocalUserService = "LocalUserService",
    LoginService = "LoginService",
    MOdService = "MOdService",
    MacroService = "MacroService",
    ManipulationService = "ManipulationService",
    MapService = "MapService",
    MatchmakingService = "MatchmakingService",
    MediaService = "MediaService",
    MeshService = "MeshService",
    MessageService = "MessageService",
    MidScoreService = "MidScoreService",
    MigrationService = "MigrationService",
    ModerationService = "ModerationService",
    ModuleScriptService = "ModuleScriptService",
    MoveService = "MoveService",
    MultiplayerService = "MultiplayerService",
    NameCallService = "NameCallService",
    NetworkClient = "NetworkClient",
    NetworkPeer = "NetworkPeer",
    NetworkServer = "NetworkServer",
    ObfuscationService = "ObfuscationService",
    ObjectCacheService = "ObjectCacheService",
    ObjectService = "ObjectService",
    OcclusionService = "OcclusionService",
    PackageService = "PackageService",
    PageService = "PageService",
    ParentService = "ParentService",
    PerfService = "PerfService",
    PersistenceService = "PersistenceService",
    PhysicsDebugService = "PhysicsDebugService",
    PlacementService = "PlacementService",
    PlatformService = "PlatformService",
    PlayService = "PlayService",
    ProceduralMeshService = "ProceduralMeshService",
    ProfanityService = "ProfanityService",
    ProgressService = "ProgressService",
    PromptService = "PromptService",
    PropertyService = "PropertyService",
    ProximityService = "ProximityService",
    PurchaseService = "PurchaseService",
    QuestService = "QuestService",
    RaycastService = "RaycastService",
    RBXAnalyticsService = "RBXAnalyticsService",
    ReactionService = "ReactionService",
    RecommendationService = "RecommendationService",
    RecordingService = "RecordingService",
    RemoteFunctionService = "RemoteFunctionService",
    RemoteService = "RemoteService",
    RenderService = "RenderService",
    ReplicationService = "ReplicationService",
    ReportService = "ReportService",
    ResumeService = "ResumeService",
    RetailService = "RetailService",
    RetargetingService = "RetargetingService",
    RigBuilderService = "RigBuilderService",
    RigService = "RigService",
    RobloxPluginService = "RobloxPluginService",
    RobloxReplicatedStorage = "RobloxReplicatedStorage",
    RulesService = "RulesService",
    SKUManager = "SKUManager",
    SKUService = "SKUService",
    SandboxService = "SandboxService",
    SceneConversionService = "SceneConversionService",
    SceneService = "SceneService",
    ScreenshotFeedbackService = "ScreenshotFeedbackService",
    ScriptService = "ScriptService",
    SearchService = "SearchService",
    SeatService = "SeatService",
    SecurityService = "SecurityService",
    SensorService = "SensorService",
    ServerHostService = "ServerHostService",
    ServerScript = "ServerScript",
    ServiceContainer = "ServiceContainer",
    ServiceProvider = "ServiceProvider",
    SessionService = "SessionService",
    SettingsService = "SettingsService",
    SimulationService = "SimulationService",
    SkeletonService = "SkeletonService",
    SkinningService = "SkinningService",
    SocialNetworkingService = "SocialNetworkingService",
    SoundGroupService = "SoundGroupService",
    SpawnLocationService = "SpawnLocationService",
    SpatialService = "SpatialService",
    SpringService = "SpringService",
    SpriteService = "SpriteService",
    StartupService = "StartupService",
    StoryService = "StoryService",
    StreamingService = "StreamingService",
    StringService = "StringService",
    StudioAssetService = "StudioAssetService",
    StudioDataService = "StudioDataService",
    StudioDeviceService = "StudioDeviceService",
    StudioGestureService = "StudioGestureService",
    StudioOnlyService = "StudioOnlyService",
    StudioPublishService = "StudioPublishService",
    StudioTestService = "StudioTestService",
    StyleService = "StyleService",
    SurfaceService = "SurfaceService",
    TaskSchedulerService = "TaskSchedulerService",
    TeamCreateService = "TeamCreateService",
    TeleportClient = "TeleportClient",
    TemplateService = "TemplateService",
    TerrainPhysicsService = "TerrainPhysicsService",
    TextFilterService = "TextFilterService",
    TexturePackService = "TexturePackService",
    ThemeService = "ThemeService",
    ThirdPartyService = "ThirdPartyService",
    ThumbnailService = "ThumbnailService",
    TileService = "TileService",
    TimeService = "TimeService",
    ToolboxService = "ToolboxService",
    TourService = "TourService",
    TransactionService = "TransactionService",
    TranslationService = "TranslationService",
    TweenServiceInternal = "TweenServiceInternal",
    UIBlurService = "UIBlurService",
    UIDragService = "UIDragService",
    UIGradientService = "UIGradientService",
    UIGridService = "UIGridService",
    UILayoutService = "UILayoutService",
    UIListLayoutService = "UIListLayoutService",
    UIPageLayoutService = "UIPageLayoutService",
    UIScaleService = "UIScaleService",
    UIScreenSizeService = "UIScreenSizeService",
    UIService = "UIService",
    UIStrokeService = "UIStrokeService",
    UITableLayoutService = "UITableLayoutService",
    UITextService = "UITextService",
    UIViewportService = "UIViewportService",
    URLService = "URLService",
    UndoService = "UndoService",
    UnitScaleService = "UnitScaleService",
    UniverseService = "UniverseService",
    UpdateService = "UpdateService",
    VFXService = "VFXService",
    VehicleService = "VehicleService",
    VideoService = "VideoService",
    ViewportService = "ViewportService",
    VisibilityService = "VisibilityService",
    VoiceService = "VoiceService",
    WaterService = "WaterService",
    WebServiceInternal = "WebServiceInternal",
    WebSocketService = "WebSocketService",
    WelcomeScreenService = "WelcomeScreenService",
    WorldRootService = "WorldRootService",
    WrappingService = "WrappingService"
}
local aK = {
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
    Debris = "Debris",
    GuiService = "GuiService",
    VirtualUser = "VirtualUser",
    VRService = "VRService",
    PhysicsService = "PhysicsService",
    AssetService = "AssetService",
    AnalyticsService = "AnalyticsService",
    GroupService = "GroupService",
    FriendsService = "FriendsService",
    TextService = "TextService",
    LocalizationService = "LocalizationService",
    MaterialService = "MaterialService",
    Selection = "Selection",
    ScriptContext = "ScriptContext",
    TestService = "TestService",
    LogService = "LogService",
    InsertService = "InsertService",
    PluginManager = "PluginManager",
    ScriptEditorService = "ScriptEditorService",
    RBXAnalyticsService = "RBXAnalyticsService",
    StudioService = "StudioService",
    ChangeHistoryService = "ChangeHistoryService",
    Mouse = "Mouse",
    KeyframeSequenceProvider = "KeyframeSequenceProvider",
    AnimationService = "AnimationService",
    BadgeService = "BadgeService",
    VoiceChatService = "VoiceChatService",
    PrivateMessagingService = "PrivateMessagingService",
    FriendMessengerService = "FriendMessengerService",
    NotificationService = "NotificationService",
    PolicyService = "PolicyService",
    StatsService = "StatsService",
    PerformanceService = "PerformanceService",
    MemoryStoreService = "MemoryStoreService",
    ServerStorage = "ServerStorage",
    ServerScriptService = "ServerScriptService",
    StarterPack = "StarterPack",
    StarterPlayer = "StarterPlayer",
    ReplicatedFirst = "ReplicatedFirst",
    SocialService = "SocialService",
    NetworkSettings = "NetworkSettings",
    TouchEnabledService = "TouchEnabledService",
    GameSettings = "GameSettings",
    FocusService = "FocusService",
    UserGameSettings = "UserGameSettings",
    UtilityService = "UtilityService",
    WebService = "WebService",
    ContentProvider = "ContentProvider",
    BasePlayerSettings = "BasePlayerSettings",
    ControllerService = "ControllerService",
    DragDetectorService = "DragDetectorService",
    FastFlags = "FastFlags",
    FlagService = "FlagService",
    FrameRateManager = "FrameRateManager",
    GamepadService = "GamepadService",
    GeometryService = "GeometryService",
    GestureService = "GestureService",
    HapticService = "HapticService",
    IconService = "IconService",
    InputService = "InputService",
    LiveOpsService = "LiveOpsService",
    MultiModalService = "MultiModalService",
    NavigationService = "NavigationService",
    ParticleEmitterService = "ParticleEmitterService",
    PointsService = "PointsService",
    PresenceService = "PresenceService",
    PurchasePromptService = "PurchasePromptService",
    ReportageService = "ReportageService",
    ScreenshotService = "ScreenshotService",
    ScreenShotService = "ScreenShotService",
    SecureMessagingService = "SecureMessagingService",
    ServerReplicatorService = "ServerReplicatorService",
    ShaderService = "ShaderService",
    SkyboxService = "SkyboxService",
    SmokeService = "SmokeService",
    StickerService = "StickerService",
    StreamableService = "StreamableService",
    TelemetryService = "TelemetryService",
    TerrainService = "TerrainService",
    TestHarnessService = "TestHarnessService",
    TestServiceLegacy = "TestServiceLegacy",
    TextureService = "TextureService",
    ToolService = "ToolService",
    TutorialService = "TutorialService",
    UserService = "UserService",
    ValueService = "ValueService",
    WeaveService = "WeaveService",
    WebGLService = "WebGLService",
    WebRequestService = "WebRequestService",
    WindowService = "WindowService",
    AccountInformationService = "AccountInformationService",
    AdService = "AdService",
    AdvancedDraggerService = "AdvancedDraggerService",
    AssetManagerService = "AssetManagerService",
    AssetThemeService = "AssetThemeService",
    AudioAnalyzerService = "AudioAnalyzerService",
    AudioService = "AudioService",
    AvatarExportService = "AvatarExportService",
    AvatarService = "AvatarService",
    BaseScriptService = "BaseScriptService",
    BasicSettings = "BasicSettings",
    BinaryDataService = "BinaryDataService",
    BodyMoverService = "BodyMoverService",
    BrowserService = "BrowserService",
    CSGDictionaryService = "CSGDictionaryService",
    CSGPersistenceService = "CSGPersistenceService",
    CSGPolygonService = "CSGPolygonService",
    CSGService = "CSGService",
    CSGSurfaceService = "CSGSurfaceService",
    CSGToolService = "CSGToolService",
    CSGValidationService = "CSGValidationService",
    CachingService = "CachingService",
    CameraScriptService = "CameraScriptService",
    CameraService = "CameraService",
    CaptchaService = "CaptchaService",
    ClickDetectorService = "ClickDetectorService",
    CloudService = "CloudService",
    ClusterService = "ClusterService",
    CommandService = "CommandService",
    CommerceService = "CommerceService",
    ConnectorService = "ConnectorService",
    ConstraintService = "ConstraintService",
    CraftService = "CraftService",
    CreatorService = "CreatorService",
    CrossDataService = "CrossDataService",
    CuratedContentService = "CuratedContentService",
    CustomEventService = "CustomEventService",
    CustomMeshService = "CustomMeshService",
    DataModel = "DataModel",
    DialogService = "DialogService",
    DisplayOrderService = "DisplayOrderService",
    DistributeService = "DistributeService",
    EmoteService = "EmoteService",
    EncoderService = "EncoderService",
    EngineService = "EngineService",
    ExperienceInviteService = "ExperienceInviteService",
    FaceAnimatorService = "FaceAnimatorService",
    FilePickerService = "FilePickerService",
    FileService = "FileService",
    ForceFeedbackService = "ForceFeedbackService",
    GamepassService = "GamepassService",
    GearService = "GearService",
    GravityService = "GravityService",
    GridService = "GridService",
    HighlightService = "HighlightService",
    HomeService = "HomeService",
    IdentityService = "IdentityService",
    ImageService = "ImageService",
    ImportService = "ImportService",
    InternalService = "InternalService",
    JobService = "JobService",
    KeyboardService = "KeyboardService",
    LMSController = "LMSController",
    LMSService = "LMSService",
    LODService = "LODService",
    LSPersistenceService = "LSPersistenceService",
    LeaderStatsService = "LeaderStatsService",
    LensService = "LensService",
    LevelOfDetailService = "LevelOfDetailService",
    LibraryService = "LibraryService",
    LightService = "LightService",
    LightingService = "LightingService",
    LocalUserService = "LocalUserService",
    LoginService = "LoginService",
    MOdService = "MOdService",
    MacroService = "MacroService",
    ManipulationService = "ManipulationService",
    MapService = "MapService",
    MatchmakingService = "MatchmakingService",
    MediaService = "MediaService",
    MeshService = "MeshService",
    MessageService = "MessageService",
    MidScoreService = "MidScoreService",
    MigrationService = "MigrationService",
    ModerationService = "ModerationService",
    ModuleScriptService = "ModuleScriptService",
    MoveService = "MoveService",
    MultiplayerService = "MultiplayerService",
    NameCallService = "NameCallService",
    NetworkClient = "NetworkClient",
    NetworkPeer = "NetworkPeer",
    NetworkServer = "NetworkServer",
    ObfuscationService = "ObfuscationService",
    ObjectCacheService = "ObjectCacheService",
    ObjectService = "ObjectService",
    OcclusionService = "OcclusionService",
    PackageService = "PackageService",
    PageService = "PageService",
    ParentService = "ParentService",
    PerfService = "PerfService",
    PersistenceService = "PersistenceService",
    PhysicsDebugService = "PhysicsDebugService",
    PlacementService = "PlacementService",
    PlatformService = "PlatformService",
    PlayService = "PlayService",
    ProceduralMeshService = "ProceduralMeshService",
    ProfanityService = "ProfanityService",
    ProgressService = "ProgressService",
    PromptService = "PromptService",
    PropertyService = "PropertyService",
    ProximityService = "ProximityService",
    PurchaseService = "PurchaseService",
    QuestService = "QuestService",
    RaycastService = "RaycastService",
    ReactionService = "ReactionService",
    RecommendationService = "RecommendationService",
    RecordingService = "RecordingService",
    RemoteFunctionService = "RemoteFunctionService",
    RemoteService = "RemoteService",
    RenderService = "RenderService",
    ReplicationService = "ReplicationService",
    ReportService = "ReportService",
    ResumeService = "ResumeService",
    RetailService = "RetailService",
    RetargetingService = "RetargetingService",
    RigBuilderService = "RigBuilderService",
    RigService = "RigService",
    RobloxPluginService = "RobloxPluginService",
    RobloxReplicatedStorage = "RobloxReplicatedStorage",
    RulesService = "RulesService",
    SKUManager = "SKUManager",
    SKUService = "SKUService",
    SandboxService = "SandboxService",
    SceneConversionService = "SceneConversionService",
    SceneService = "SceneService",
    ScreenshotFeedbackService = "ScreenshotFeedbackService",
    ScriptService = "ScriptService",
    SearchService = "SearchService",
    SeatService = "SeatService",
    SecurityService = "SecurityService",
    SensorService = "SensorService",
    ServerHostService = "ServerHostService",
    ServerScript = "ServerScript",
    ServiceContainer = "ServiceContainer",
    ServiceProvider = "ServiceProvider",
    SessionService = "SessionService",
    SettingsService = "SettingsService",
    SimulationService = "SimulationService",
    SkeletonService = "SkeletonService",
    SkinningService = "SkinningService",
    SocialNetworkingService = "SocialNetworkingService",
    SoundGroupService = "SoundGroupService",
    SpawnLocationService = "SpawnLocationService",
    SpatialService = "SpatialService",
    SpringService = "SpringService",
    SpriteService = "SpriteService",
    StartupService = "StartupService",
    StoryService = "StoryService",
    StreamingService = "StreamingService",
    StringService = "StringService",
    StudioAssetService = "StudioAssetService",
    StudioDataService = "StudioDataService",
    StudioDeviceService = "StudioDeviceService",
    StudioGestureService = "StudioGestureService",
    StudioOnlyService = "StudioOnlyService",
    StudioPublishService = "StudioPublishService",
    StudioTestService = "StudioTestService",
    StyleService = "StyleService",
    SurfaceService = "SurfaceService",
    TaskSchedulerService = "TaskSchedulerService",
    TeamCreateService = "TeamCreateService",
    TeleportClient = "TeleportClient",
    TemplateService = "TemplateService",
    TerrainPhysicsService = "TerrainPhysicsService",
    TextFilterService = "TextFilterService",
    TexturePackService = "TexturePackService",
    ThemeService = "ThemeService",
    ThirdPartyService = "ThirdPartyService",
    ThumbnailService = "ThumbnailService",
    TileService = "TileService",
    TimeService = "TimeService",
    ToolboxService = "ToolboxService",
    TourService = "TourService",
    TransactionService = "TransactionService",
    TranslationService = "TranslationService",
    TweenServiceInternal = "TweenServiceInternal",
    UIBlurService = "UIBlurService",
    UIDragService = "UIDragService",
    UIGradientService = "UIGradientService",
    UIGridService = "UIGridService",
    UILayoutService = "UILayoutService",
    UIListLayoutService = "UIListLayoutService",
    UIPageLayoutService = "UIPageLayoutService",
    UIScaleService = "UIScaleService",
    UIScreenSizeService = "UIScreenSizeService",
    UIService = "UIService",
    UIStrokeService = "UIStrokeService",
    UITableLayoutService = "UITableLayoutService",
    UITextService = "UITextService",
    UIViewportService = "UIViewportService",
    URLService = "URLService",
    UndoService = "UndoService",
    UnitScaleService = "UnitScaleService",
    UniverseService = "UniverseService",
    UpdateService = "UpdateService",
    VFXService = "VFXService",
    VehicleService = "VehicleService",
    VideoService = "VideoService",
    ViewportService = "ViewportService",
    VisibilityService = "VisibilityService",
    VoiceService = "VoiceService",
    WaterService = "WaterService",
    WebServiceInternal = "WebServiceInternal",
    WebSocketService = "WebSocketService",
    WelcomeScreenService = "WelcomeScreenService",
    WorldRootService = "WorldRootService",
    WrappingService = "WrappingService"
}
local aL = {
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
local aM = {}
local function aN(aO)
    aM[aO] = (aM[aO] or 0) + 1
    return aM[aO]
end
local function aP(aQ, aR, aS)
    if not aQ then
        aQ = "var"
    end
    local aT = aE(aQ)
    if aK[aT] then
        return aK[aT]
    end
    if aS then
        local aU = aS:lower()
        for W, aV in ipairs(aL) do
            if aU:find(aV.pattern) then
                local a2 = aN(aV.counter)
                return a2 == 1 and aV.prefix or aV.prefix .. a2
            end
        end
    end
    if aT == "LocalPlayer" then
        return "LocalPlayer"
    end
    if aT == "Character" then
        return "Character"
    end
    if aT == "Humanoid" then
        return "Humanoid"
    end
    if aT == "HumanoidRootPart" then
        return "HumanoidRootPart"
    end
    if aT == "Camera" then
        return "Camera"
    end
    if aT:match("^Enum%.") then
        return aT
    end
    local T = aT:gsub("[^%w_]", '"'):gsub("^%d+", '"')
    if T == '"' or T == "Object" or T == "Value" or T == "result" then
        T = "var"
    end
    return T
end
local function aW(x, aQ, aX, aS)
    local aY = t.registry[x]
    if aY and aY:match("^lar%d+$") then
        return aY
    end
    t.lar_counter = (t.lar_counter or 0) + 1
    local am = "Var" .. t.lar_counter
    t.names_used[am] = true
    t.registry[x] = am
    t.reverse_registry[am] = x
    t.variable_types[am] = aX or j(x)
    return am
end
local function aZ(aF, a_, b0, b1)
    a_ = a_ or 0
    b0 = b0 or {}
    if a_ > r.MAX_DEPTH then
        return "{ --[[max depth]] }"
    end
    local b2 = j(aF)
    if w(aF) then
        local b3 = rawget(aF, "__value")
        return m(b3 or 0)
    end
    if b2 == "table" and t.registry[aF] then
        return t.registry[aF]
    end
    if b2 == "nil" then
        return "nil"
    elseif b2 == "string" then
        if #aF > 100 and aF:match("^[A-Za-z0-9+/=]+$") then
            table.insert(t.string_refs, {value = aF:sub(1, 50) .. "...", hint = "base64", full_length = #aF})
        elseif aF:match("https?://") then
            table.insert(t.string_refs, {value = aF, hint = "URL"})
        elseif aF:match("rbxasset://") or aF:match("rbxassetid://") then
            table.insert(t.string_refs, {value = aF, hint = "Asset"})
        end
        return aH(aF)
    elseif b2 == "number" then
        if aF ~= aF then
            return "0/0"
        end
        if aF == math.huge then
            return "math.huge"
        end
        if aF == -math.huge then
            return "-math.huge"
        end
        if aF == math.floor(aF) then
            return m(math.floor(aF))
        end
        return string.format("%.6g", aF)
    elseif b2 == "boolean" then
        return m(aF)
    elseif b2 == "function" then
        if t.registry[aF] then
            return t.registry[aF]
        end
        return "function() end"
    elseif b2 == "table" then
        if G(aF) then
            return t.registry[aF] or "proxy"
        end
        if b0[aF] then
            return "{ --[[circular]] }"
        end
        b0[aF] = true
        local a2 = 0
        for b4, b5 in D(aF) do
            if b4 ~= F and b4 ~= "__proxy_id" then
                a2 = a2 + 1
            end
        end
        if a2 == 0 then
            return "{}"
        end
        local b6 = true
        local b7 = 0
        for b4, b5 in D(aF) do
            if b4 ~= F and b4 ~= "__proxy_id" then
                if j(b4) ~= "number" or b4 < 1 or b4 ~= math.floor(b4) then
                    b6 = false
                    break
                else
                    b7 = math.max(b7, b4)
                end
            end
        end
        b6 = b6 and b7 == a2
        if b6 and a2 <= 5 and b1 ~= false then
            local b8 = {}
            for L = 1, a2 do
                local b5 = aF[L]
                if j(b5) ~= "table" or G(b5) then
                    table.insert(b8, aZ(b5, a_ + 1, b0, true))
                else
                    b6 = false
                    break
                end
            end
            if b6 and #b8 == a2 then
                return "{" .. table.concat(b8, ", ") .. "}"
            end
        end
        local b9 = {}
        local ba = 0
        local bb = string.rep("    ", t.indent + a_ + 1)
        local bc = string.rep("    ", t.indent + a_)
        for b4, b5 in D(aF) do
            if b4 ~= F and b4 ~= "__proxy_id" then
                ba = ba + 1
                if ba > r.MAX_TABLE_ITEMS then
                    table.insert(b9, bb .. "-- ..." .. a2 - ba + 1 .. " more")
                    break
                end
                local bd
                if b6 then
                    bd = nil
                elseif j(b4) == "string" and b4:match("^[%a_][%w_]*$") then
                    bd = b4
                else
                    bd = "[" .. aZ(b4, a_ + 1, b0) .. "]"
                end
                local be = aZ(b5, a_ + 1, b0)
                if bd then
                    table.insert(b9, bb .. bd .. " = " .. be)
                else
                    table.insert(b9, bb .. be)
                end
            end
        end
        if #b9 == 0 then
            return "{}"
        end
        return "{\n" .. table.concat(b9, ",\n") .. "\n" .. bc .. "}"
    elseif b2 == "userdata" then
        if t.registry[aF] then
            return t.registry[aF]
        end
        local y, O = pcall(m, aF)
        return y and O or "userdata"
    elseif b2 == "thread" then
        return "coroutine.create(function() end)"
    else
        local y, O = pcall(m, aF)
        return y and O or "nil"
    end
end
local bf = {}
setmetatable(bf, {__mode = "k"})
local function bg()
    local bh = {}
    bf[bh] = true
    local bi = {}
    setmetatable(bh, bi)
    return bh, bi
end
local function G(x)
    return bf[x] == true
end
local bj
local bk
local function bl(bm)
    local bh, bi = bg()
    rawset(bh, v, true)
    rawset(bh, "__value", bm)
    t.registry[bh] = tostring(bm)
    bi.__tostring = function()
        return tostring(bm)
    end
    bi.__index = function(b2, b4)
        if b4 == F or b4 == "__proxy_id" or b4 == v or b4 == "__value" then
            return rawget(b2, b4)
        end
        return bl(0)
    end
    bi.__newindex = function()
    end
    bi.__call = function()
        return bm
    end
    local function bn(X)
        return function(bo, aa)
            local bp = type(bo) == "table" and rawget(bo, "__value") or bo or 0
            local bq = type(aa) == "table" and rawget(aa, "__value") or aa or 0
            local z
            if X == "+" then
                z = bp + bq
            elseif X == "-" then
                z = bp - bq
            elseif X == "*" then
                z = bp * bq
            elseif X == "/" then
                z = bq ~= 0 and bp / bq or 0
            elseif X == "%" then
                z = bq ~= 0 and bp % bq or 0
            elseif X == "^" then
                z = bp ^ bq
            else
                z = 0
            end
            return bl(z)
        end
    end
    bi.__add = bn("+")
    bi.__sub = bn("-")
    bi.__mul = bn("*")
    bi.__div = bn("/")
    bi.__mod = bn("%")
    bi.__pow = bn("^")
    bi.__unm = function(bo)
        return bl(-(rawget(bo, "__value") or 0))
    end
    bi.__eq = function(bo, aa)
        local bp = type(bo) == "table" and rawget(bo, "__value") or bo
        local bq = type(aa) == "table" and rawget(aa, "__value") or aa
        return bp == bq
    end
    bi.__lt = function(bo, aa)
        local bp = type(bo) == "table" and rawget(bo, "__value") or bo
        local bq = type(aa) == "table" and rawget(aa, "__value") or aa
        return bp < bq
    end
    bi.__le = function(bo, aa)
        local bp = type(bo) == "table" and rawget(bo, "__value") or bo
        local bq = type(aa) == "table" and rawget(aa, "__value") or aa
        return bp <= bq
    end
    bi.__len = function()
        return 0
    end
    return bh
end
local function br(bs, bt)
    if j(bs) ~= "function" then
        return {}
    end
    local a4 = #t.output
    local bu = t.pending_iterator
    t.pending_iterator = false
    xpcall(
        function()
            bs(table.unpack(bt or {}))
        end,
        function()
        end
    )
    while t.pending_iterator do
        t.indent = t.indent - 1
        at("end")
        t.pending_iterator = false
    end
    t.pending_iterator = bu
    local bv = {}
    for L = a4 + 1, #t.output do
        table.insert(bv, t.output[L])
    end
    for L = #t.output, a4 + 1, -1 do
        table.remove(t.output, L)
    end
    return bv
end
bk = function(aS, bw)
    local bh, bi = bg()
    local bx = t.registry[bw] or "object"
    local by = aE(aS)
    t.registry[bh] = bx .. "." .. by
    bi.__call = function(self, bz, ...)
        local bA
        if bz == bh or bz == bw or G(bz) then
            bA = {...}
        else
            bA = {bz, ...}
        end
        local aU = by:lower()
        local bB = nil
        local bC = true
        for W, aV in ipairs(aL) do
            if aU:find(aV.pattern) then
                bB = aV.prefix
                break
            end
        end
        local bD = nil
        local bE = nil
        local bF = nil
        for L, b5 in ipairs(bA) do
            if j(b5) == "function" then
                bD = b5
                break
            elseif j(b5) == "table" and not G(b5) then
                for bG, aF in D(b5) do
                    local bH = m(bG):lower()
                    if bH == "callback" and j(aF) == "function" then
                        bD = aF
                        bE = bG
                        bF = L
                        break
                    end
                end
            end
        end
        local bI = "value"
        local bt = {}
        if bD then
            if aU:match("toggle") then
                bI = "enabled"
                bt = {true}
            elseif aU:match("slider") then
                bI = "value"
                bt = {50}
            elseif aU:match("dropdown") then
                bI = "selected"
                bt = {"Option"}
            elseif aU:match("textbox") or aU:match("input") then
                bI = "text"
                bt = {s or "input"}
            elseif aU:match("keybind") or aU:match("bind") then
                bI = "key"
                bt = {bj("Enum.KeyCode.E", false)}
            elseif aU:match("color") then
                bI = "color"
                bt = {Color3.fromRGB(255, 255, 255)}
            elseif aU:match("button") then
                bI = "\\"
                bt = {}
            end
        end
        local bJ = {}
        if bD then
            bJ = br(bD, bt)
        end
        local z = bj(bB or by, false, bw)
        local _ = aW(z, bB or by, nil, by)
        local bK = {}
        for L, b5 in ipairs(bA) do
            if j(b5) == "table" and not G(b5) and L == bF then
                local b8 = {}
                for bG, aF in D(b5) do
                    local bd
                    if j(bG) == "string" and bG:match("^[%a_][%w_]*$") then
                        bd = bG
                    else
                        bd = "[" .. aZ(bG) .. "]"
                    end
                    if bG == bE and #bJ > 0 then
                        local bL = bI ~= '"' and "function(" .. "bI" .. ")" or "function()"
                        local bb = string.rep("    ", t.indent + 2)
                        local bM = {}
                        for W, aw in ipairs(bJ) do
                            table.insert(bM, bb .. (aw:match("^%s*(.*)$") or aw))
                        end
                        local bc = string.rep("    ", t.indent + 1)
                        table.insert(b8, bd .. " = " .. bL .. "\n" .. table.concat(bM, "\n") .. "\n" .. bc .. "end")
                    elseif bG == bE then
                        local bN = bI ~= "\\" and "function(" .. bI .. ") end" or "function() end"
                        table.insert(b8, bd .. " = " .. bN)
                    else
                        table.insert(b8, bd .. " = " .. aZ(aF))
                    end
                end
                table.insert(
                    bK,
                    "{\n" ..
                        string.rep("    ", t.indent + 1) ..
                            table.concat(b8, ",\n" .. string.rep("    ", t.indent + 1)) ..
                                "\n" .. string.rep("    ", t.indent) .. "}"
                )
            elseif j(b5) == "function" then
                if #bJ > 0 then
                    local bL = bI ~= '"' and "function(" .. bI .. ")" or "function()"
                    local bb = string.rep("    ", t.indent + 1)
                    local bM = {}
                    for W, aw in ipairs(bJ) do
                        table.insert(bM, bb .. (aw:match("^%s*(.*)$") or aw))
                    end
                    table.insert(
                        bK,
                        bL .. "\n" .. table.concat(bM, "\n") .. "\n" .. string.rep("    ", t.indent) .. "end"
                    )
                else
                    local bN = bI ~= '"' and "function(" .. bI .. ") end" or "function() end"
                    table.insert(bK, bN)
                end
            else
                table.insert(bK, aZ(b5))
            end
        end
        at(string.format("local %s = %s:%s(%s)", _, bx, by, table.concat(bK, ", ")))
        return z
    end
    bi.__index = function(b2, b4)
        if b4 == F or b4 == "__proxy_id" then
            return rawget(b2, b4)
        end
        return bk(b4, bh)
    end
    bi.__tostring = function()
        return bx .. ":" .. by
    end
    return bh
end
local _script_registry = {}
local _script_registry_set = {}
local function _register_script_proxy(x, name)
    local n = tostring(name or "")
    if not _script_registry_set[x] then
        _script_registry_set[x] = true
        table.insert(_script_registry, x)
    end
end

bj = function(aQ, bO, bw)
    local bh, bi = bg()
    local aT = aE(aQ)
    t.property_store[bh] = {}
    if bO then
        t.registry[bh] = aT
        t.names_used[aT] = true
    elseif bw then
        t.parent_map[bh] = bw
        rawset(bh, "__temp_path", (t.registry[bw] or "object") .. "." .. aT)
    end
    local bP = {}
    bP.LogEvent = function(self, eventName, parameters)
    local bS = t.registry[bh] or "RBXAnalyticsService"
    at(string.format("%s:LogEvent(%s, %s)", bS, aH(eventName), aZ(parameters or {})))
    table.insert(t.call_graph, {type = "AnalyticsEvent", name = "LogEvent", eventName = eventName, parameters = parameters})
    return true
end

bP.LogCustomEvent = function(self, eventName, eventData)
    local bS = t.registry[bh] or "RBXAnalyticsService"
    at(string.format("%s:LogCustomEvent(%s, %s)", bS, aH(eventName), aH(eventData or "")))
    return true
end

bP.LogSessionStart = function(self, sessionData)
    local bS = t.registry[bh] or "RBXAnalyticsService"
    at(string.format("%s:LogSessionStart(%s)", bS, aZ(sessionData or {})))
    return true
end

bP.LogSessionEnd = function(self, sessionData)
    local bS = t.registry[bh] or "RBXAnalyticsService"
    at(string.format("%s:LogSessionEnd(%s)", bS, aZ(sessionData or {})))
    return true
end

bP.GetAnalyticsData = function(self)
    local bS = t.registry[bh] or "RBXAnalyticsService"
    local proxy = bj("AnalyticsData", false)
    local _ = aW(proxy, "analyticsData")
    at(string.format("local %s = %s:GetAnalyticsData()", _, bS))
    return proxy
end

bP.SetUserId = function(self, userId)
    local bS = t.registry[bh] or "RBXAnalyticsService"
    at(string.format("%s:SetUserId(%s)", bS, aZ(userId)))
    return true
end

bP.SetSessionId = function(self, sessionId)
    local bS = t.registry[bh] or "RBXAnalyticsService"
    at(string.format("%s:SetSessionId(%s)", bS, aH(sessionId)))
    return true
end

bP.Flush = function(self)
    local bS = t.registry[bh] or "RBXAnalyticsService"
    at(string.format("%s:Flush()", bS))
    return true
end
    bP.GetService = function(self, bQ)
        local bR = aE(bQ)
        local x = bj(bR, false, bh)
        local _ = aW(x, bR)
        local bS = t.registry[bh] or "game"
        at(string.format("local %s = %s:GetService(%s)", _, bS, aH(bR)))
        return x
    end
    bP.WaitForChild = function(self, bT, bU)
        local bV = aE(bT)
        local x = bj(bV, false, bh)
        local _ = aW(x, bV)
        local bS = t.registry[bh] or "object"
        if bU then
            at(string.format("local %s = %s:WaitForChild(%s, %s)", _, bS, aH(bV), aZ(bU)))
        else
            at(string.format("local %s = %s:WaitForChild(%s)", _, bS, aH(bV)))
        end
        return x
    end
    bP.FindFirstChild = function(self, bT, bW)
        local bV = aE(bT)
        local x = bj(bV, false, bh)
        local _ = aW(x, bV)
        local bS = t.registry[bh] or "object"
        if bW then
            at(string.format("local %s = %s:FindFirstChild(%s, true)", _, bS, aH(bV)))
        else
            at(string.format("local %s = %s:FindFirstChild(%s)", _, bS, aH(bV)))
        end
        _register_script_proxy(x, bV)
        return x
    end
    bP.FindFirstChildOfClass = function(self, bX)
        local bY = aE(bX)
        local x = bj(bY, false, bh)
        local _ = aW(x, bY)
        local bS = t.registry[bh] or "object"
        at(string.format("local %s = %s:FindFirstChildOfClass(%s)", _, bS, aH(bY)))
        return x
    end
    bP.FindFirstChildWhichIsA = function(self, bX)
        local bY = aE(bX)
        local x = bj(bY, false, bh)
        local _ = aW(x, bY)
        local bS = t.registry[bh] or "object"
        at(string.format("local %s = %s:FindFirstChildWhichIsA(%s)", _, bS, aH(bY)))
        return x
    end
    bP.FindFirstAncestor = function(self, am)
        local bZ = aE(am)
        local x = bj(bZ, false, bh)
        local _ = aW(x, bZ)
        local bS = t.registry[bh] or "object"
        at(string.format("local %s = %s:FindFirstAncestor(%s)", _, bS, aH(bZ)))
        return x
    end
    bP.FindFirstAncestorOfClass = function(self, bX)
        local bY = aE(bX)
        local x = bj(bY, false, bh)
        local _ = aW(x, bY)
        local bS = t.registry[bh] or "object"
        at(string.format("local %s = %s:FindFirstAncestorOfClass(%s)", _, bS, aH(bY)))
        return x
    end
    bP.FindFirstAncestorWhichIsA = function(self, bX)
        local bY = aE(bX)
        local x = bj(bY, false, bh)
        local _ = aW(x, bY)
        local bS = t.registry[bh] or "object"
        at(string.format("local %s = %s:FindFirstAncestorWhichIsA(%s)", _, bS, aH(bY)))
        return x
    end
    bP.GetChildren = function(self)
        local bS = t.registry[bh] or "object"
        local children_list = {}
        if t.property_store[bh] and t.property_store[bh].Children then
            children_list = t.property_store[bh].Children
        end
        at(string.format("-- %s:GetChildren() returned %d items", bS, #children_list))
        return children_list
    end
    bP.GetDescendants = function(self)
        local bS = t.registry[bh] or "object"
        local descendants = {}
        local function collect(node)
            if t.property_store[node] and t.property_store[node].Children then
                for _, child in ipairs(t.property_store[node].Children) do
                    table.insert(descendants, child)
                    collect(child)
                end
            end
        end
        collect(bh)
        at(string.format("-- %s:GetDescendants() returned %d items", bS, #descendants))
        return descendants
    end
    bP.Clone = function(self)
        local bS = t.registry[bh] or "object"
        local x = bj((aT or "object") .. "Clone", false)
        local _ = aW(x, (aT or "object") .. "Clone")
        at(string.format("local %s = %s:Clone()", _, bS))
        return x
    end
    bP.Destroy = function(self)
        local bS = t.registry[bh] or "object"
        at(string.format("%s:Destroy()", bS))
    end
    bP.ClearAllChildren = function(self)
        local bS = t.registry[bh] or "object"
        at(string.format("%s:ClearAllChildren()", bS))
        if t.property_store[bh] and t.property_store[bh].Children then
            local children_copy = {}
            for _, child in ipairs(t.property_store[bh].Children) do
                table.insert(children_copy, child)
            end
            for _, child in ipairs(children_copy) do
                if t.property_store[child] then
                    t.property_store[child].Parent = nil
                end
                t.parent_map[child] = nil
            end
            t.property_store[bh].Children = {}
        end
    end
    bP.Connect = function(self, bs)
        local bS = t.registry[bh] or "signal"
        local c1 = bj("connection", false)
        local c2 = aW(c1, "conn")
        local c3 = bS:match("%.([^%.]+)$") or bS
        local c4 = {"..."}
        if c3:match("InputBegan") or c3:match("InputEnded") or c3:match("InputChanged") then
            c4 = {"input", "gameProcessed"}
        elseif c3:match("CharacterAdded") or c3:match("CharacterRemoving") then
            c4 = {"character"}
        elseif c3:match("PlayerAdded") or c3:match("PlayerRemoving") then
            c4 = {"player"}
        elseif c3:match("Touched") or c3:match("TouchEnded") then
            c4 = {"hit"}
        elseif c3:match("Heartbeat") or c3:match("RenderStepped") then
            c4 = {"deltaTime"}
        elseif c3:match("Stepped") then
            c4 = {"time", "deltaTime"}
        elseif c3:match("Changed") or c3:match("GetPropertyChangedSignal") then
            c4 = {"property"}
        elseif c3:match("ChildAdded") or c3:match("ChildRemoved") then
            c4 = {"child"}
        elseif c3:match("DescendantAdded") or c3:match("DescendantRemoving") then
            c4 = {"descendant"}
        elseif c3:match("AncestryChanged") then
            c4 = {"child", "parent"}
        elseif c3:match("Died") or c3:match("MouseButton") or c3:match("Activated") then
            c4 = {}
        elseif c3:match("FocusLost") then
            c4 = {"enterPressed", "inputObject"}
        elseif c3:match("Focused") then
            c4 = {}
        elseif c3:match("MouseEnter") or c3:match("MouseLeave") then
            c4 = {}
        elseif c3:match("MouseMoved") then
            c4 = {"x", "y"}
        elseif c3:match("SelectionGained") or c3:match("SelectionLost") then
            c4 = {}
        elseif c3:match("JumpRequest") then
            c4 = {}
        elseif c3:match("StateChanged") then
            c4 = {"oldState", "newState"}
        elseif c3:match("HealthChanged") then
            c4 = {"health"}
        elseif c3:match("Running") then
            c4 = {"speed"}
        elseif c3:match("FreeFalling") then
            c4 = {"isFalling"}
        elseif c3:match("Climbing") then
            c4 = {"speed"}
        elseif c3:match("Seated") then
            c4 = {"isSeated", "seatPart"}
        elseif c3:match("MoveToFinished") then
            c4 = {"reached"}
        elseif c3:match("OnClientEvent") then
            c4 = {"..."}
        elseif c3:match("OnServerEvent") then
            c4 = {"player", "..."}
        elseif c3:match("RemoteOnInvokeServer") then
            c4 = {"player", "..."}
        elseif c3:match("RemoteOnInvokeClient") then
            c4 = {"..."}
        elseif c3:match("PromptButtonHoldBegan") or c3:match("PromptButtonHoldEnded") then
            c4 = {"player"}
        elseif c3:match("Triggered") then
            c4 = {"player"}
        elseif c3:match("AnimationPlayed") then
            c4 = {"track"}
        elseif c3:match("Stopped") then
            c4 = {}
        elseif c3:match("KeyframeReached") then
            c4 = {"keyframeName"}
        elseif c3:match("MarkerReached") then
            c4 = {"markerName"}
        elseif c3:match("Completed") then
            c4 = {"playbackState"}
        elseif c3:match("ItemAdded") or c3:match("ItemRemoved") then
            c4 = {"item"}
        elseif c3:match("Collision") then
            c4 = {"part"}
        elseif c3:match("Chatted") then
            c4 = {"message"}
        elseif c3:match("TeamChanged") then
            c4 = {"team"}
        end
        at(string.format("local %s = %s:Connect(function(%s)", c2, bS, table.concat(c4, ", ")))
        t.indent = t.indent + 1
        if j(bs) == "function" then
            xpcall(
                function()
                    bs()
                end,
                function()
                end
            )
        end
        while t.pending_iterator do
            t.indent = t.indent - 1
            at("end")
            t.pending_iterator = false
        end
        t.indent = t.indent - 1
        at("end)")
        return c1
    end
    bP.Once = function(self, bs)
        local bS = t.registry[bh] or "signal"
        local c1 = bj("connection", false)
        local c2 = aW(c1, "conn")
        at(string.format("local %s = %s:Once(function(...)", c2, bS))
        t.indent = t.indent + 1
        if j(bs) == "function" then
            xpcall(
                function()
                    bs()
                end,
                function()
                end
            )
        end
        t.indent = t.indent - 1
        at("end)")
        return c1
    end
    bP.Wait = function(self)
        local bS = t.registry[bh] or "signal"
        local z = bj("waitResult", false)
        local _ = aW(z, "waitResult")
        at(string.format("local %s = %s:Wait()", _, bS))
        return z
    end
    bP.Disconnect = function(self)
        local bS = t.registry[bh] or "connection"
        at(string.format("%s:Disconnect()", bS))
    end
    bP.FireServer = function(self, ...)
        local bS = t.registry[bh] or "remote"
        local bA = {...}
        local c5 = {}
        for W, b5 in ipairs(bA) do
            table.insert(c5, aZ(b5))
        end
        at(string.format("%s:FireServer(%s)", bS, table.concat(c5, ", ")))
        table.insert(t.call_graph, {type = "RemoteEvent", name = bS, args = bA})
    end
    bP.InvokeServer = function(self, ...)
        local bS = t.registry[bh] or "remote"
        local bA = {...}
        local c5 = {}
        for W, b5 in ipairs(bA) do
            table.insert(c5, aZ(b5))
        end
        local z = bj("invokeResult", false)
        local _ = aW(z, "result")
        at(string.format("local %s = %s:InvokeServer(%s)", _, bS, table.concat(c5, ", ")))
        table.insert(t.call_graph, {type = "RemoteFunction", name = bS, args = bA})
        return z
    end
    bP.Create = function(self, x, c6, c7)
        local bS = t.registry[bh] or "TweenService"
        local c8 = bj("tween", false)
        local _ = aW(c8, "tween")
        at(string.format("local %s = %s:Create(%s, %s, %s)", _, bS, aZ(x), aZ(c6), aZ(c7)))
        return c8
    end
    bP.Play = function(self)
        local bS = t.registry[bh] or "tween"
        at(string.format("%s:Play()", bS))
        if self._tween_info and self._tween_info._duration then
            self._start_time = os.clock()
            self._duration = self._tween_info._duration
        end
    end
    bP.Pause = function(self)
        local bS = t.registry[bh] or "tween"
        at(string.format("%s:Pause()", bS))
    end
    bP.Cancel = function(self)
        local bS = t.registry[bh] or "tween"
        at(string.format("%s:Cancel()", bS))
    end
    bP.GetValue = function(self, t, style, direction)
        if style == "Linear" then
            return t
        elseif style == "Quad" then
            if direction == "In" then
                return t * t
            elseif direction == "Out" then
                return t * (2 - t)
            else
                return t < 0.5 and 2 * t * t or -1 + (4 - 2 * t) * t
            end
        elseif style == "Sine" then
            if direction == "In" then
                return 1 - math.cos(t * math.pi / 2)
            elseif direction == "Out" then
                return math.sin(t * math.pi / 2)
            else
                return (1 - math.cos(math.pi * t)) / 2
            end
        end
        return t
    end
    bP._completedSignal = nil
    bP._getCompletedSignal = function(self)
        if not self._completedSignal then
            local sig = bj("RBXScriptSignal", false)
            self._completedSignal = sig
            local dur = self._duration or 0.1
            sig.Wait = function()
                local st = os.clock()
                while os.clock() - st < dur do task.wait() end
                return true
            end
            sig.Connect = function(s, cb)
                task.spawn(function()
                    if self._duration then task.wait(self._duration) end
                    if cb then pcall(cb) end
                end)
                return {Disconnect = function() end}
            end
        end
        return self._completedSignal
    end
    bP.Completed = nil
    bP.Stop = function(self)
        local bS = t.registry[bh] or "tween"
        at(string.format("%s:Stop()", bS))
    end
    bP.Raycast = function(self, c9, ca, cb)
        local bS = t.registry[bh] or "workspace"
        local z = bj("raycastResult", false)
        local _ = aW(z, "rayResult")
        if cb then
            at(string.format("local %s = %s:Raycast(%s, %s, %s)", _, bS, aZ(c9), aZ(ca), aZ(cb)))
        else
            at(string.format("local %s = %s:Raycast(%s, %s)", _, bS, aZ(c9), aZ(ca)))
        end
        return z
    end
    bP.GetMouse = function(self)
        local bS = t.registry[bh] or "player"
        local cc = bj("mouse", false)
        local _ = aW(cc, "mouse")
        at(string.format("local %s = %s:GetMouse()", _, bS))
        return cc
    end
    bP.Kick = function(self, cd)
        local bS = t.registry[bh] or "player"
        if cd then
            at(string.format("%s:Kick(%s)", bS, aZ(cd)))
        else
            at(string.format("%s:Kick()", bS))
        end
    end
    bP.GetPropertyChangedSignal = function(self, ce)
        local cf = aE(ce)
        local bS = t.registry[bh] or "instance"
        local cg = bj(cf .. "Changed", false)
        t.registry[cg] = bS .. ":GetPropertyChangedSignal(" .. aH(cf) .. ")"
        return cg
    end
    bP.IsA = function(self, bX)
        return true
    end
    bP.IsDescendantOf = function(self, ch)
        return true
    end
    bP.IsAncestorOf = function(self, ci)
        return true
    end
    bP.GetAttribute = function(self, cj)
        local bS = t.registry[bh] or "instance"
        at(string.format("-- %s:GetAttribute(%s)", bS, aH(cj)))
        if not t.property_store[bh] then
            t.property_store[bh] = {}
        end
        if not t.property_store[bh].Attributes then
            t.property_store[bh].Attributes = {}
        end
        return t.property_store[bh].Attributes[cj]
    end
    bP.SetAttribute = function(self, cj, bm)
        local bS = t.registry[bh] or "instance"
        if not t.property_store[bh] then
            t.property_store[bh] = {}
        end
        if not t.property_store[bh].Attributes then
            t.property_store[bh].Attributes = {}
        end
        t.property_store[bh].Attributes[cj] = bm
        at(string.format("%s:SetAttribute(%s, %s)", bS, aH(cj), aZ(bm)))
    end
    bP.GetAttributes = function(self)
        return {}
    end
    bP.GetPlayers = function(self)
        return {}
    end
    bP.GetPlayerFromCharacter = function(self, ck)
        local bS = t.registry[bh] or "Players"
        local cl = bj("player", false)
        local _ = aW(cl, "player")
        at(string.format("local %s = %s:GetPlayerFromCharacter(%s)", _, bS, aZ(ck)))
        return cl
    end
    bP.GetPlayerByUserId = function(self, cm)
        local bS = t.registry[bh] or "Players"
        local cl = bj("player", false)
        local _ = aW(cl, "player")
        at(string.format("local %s = %s:GetPlayerByUserId(%s)", _, bS, aZ(cm)))
        return cl
    end
    bP.SetCore = function(self, am, bm)
        local bS = t.registry[bh] or "StarterGui"
        at(string.format("%s:SetCore(%s, %s)", bS, aH(am), aZ(bm)))
    end
    bP.GetCore = function(self, am)
        return nil
    end
    bP.SetCoreGuiEnabled = function(self, cn, co)
        local bS = t.registry[bh] or "StarterGui"
        at(string.format("%s:SetCoreGuiEnabled(%s, %s)", bS, aZ(cn), aZ(co)))
    end
    bP.BindToRenderStep = function(self, am, cp, bs)
        local bS = t.registry[bh] or "RunService"
        at(string.format("%s:BindToRenderStep(%s, %s, function(deltaTime)", bS, aH(am), aZ(cp)))
        t.indent = t.indent + 1
        if j(bs) == "function" then
            xpcall(
                function()
                    bs(0.016)
                end,
                function()
                end
            )
        end
        t.indent = t.indent - 1
        at("end)")
    end
    bP.UnbindFromRenderStep = function(self, am)
        local bS = t.registry[bh] or "RunService"
        at(string.format("%s:UnbindFromRenderStep(%s)", bS, aH(am)))
    end
    bP.GetFullName = function(self)
        return t.registry[bh] or "Instance"
    end
    bP.GetDebugId = function(self)
        return "DEBUG_" .. (H(bh) or "0")
    end
    bP.MoveTo = function(self, cq, cr)
        local bS = t.registry[bh] or "humanoid"
        if cr then
            at(string.format("%s:MoveTo(%s, %s)", bS, aZ(cq), aZ(cr)))
        else
            at(string.format("%s:MoveTo(%s)", bS, aZ(cq)))
        end
    end
    bP.Move = function(self, ca, cs)
        local bS = t.registry[bh] or "humanoid"
        at(string.format("%s:Move(%s, %s)", bS, aZ(ca), aZ(cs or false)))
    end
    bP.EquipTool = function(self, ct)
        local bS = t.registry[bh] or "humanoid"
        at(string.format("%s:EquipTool(%s)", bS, aZ(ct)))
    end
    bP.UnequipTools = function(self)
        local bS = t.registry[bh] or "humanoid"
        at(string.format("%s:UnequipTools()", bS))
    end
    bP.TakeDamage = function(self, cu)
        local bS = t.registry[bh] or "humanoid"
        at(string.format("%s:TakeDamage(%s)", bS, aZ(cu)))
    end
    bP.ChangeState = function(self, cv)
        local bS = t.registry[bh] or "humanoid"
        at(string.format("%s:ChangeState(%s)", bS, aZ(cv)))
    end
    bP.SetStateEnabled = function(self, state, enabled)
        local bS = t.registry[bh] or "humanoid"
        at(string.format("%s:SetStateEnabled(%s, %s)", bS, aZ(state), aZ(enabled)))
    end
    bP.GetState = function(self)
        return bj("Enum.HumanoidStateType.Running", false)
    end
    bP.SetPrimaryPartCFrame = function(self, cw)
        local bS = t.registry[bh] or "model"
        at(string.format("%s:SetPrimaryPartCFrame(%s)", bS, aZ(cw)))
    end
    bP.GetPrimaryPartCFrame = function(self)
        return CFrame.new(0, 0, 0)
    end
    bP.PivotTo = function(self, cw)
        local bS = t.registry[bh] or "model"
        at(string.format("%s:PivotTo(%s)", bS, aZ(cw)))
    end
    bP.GetPivot = function(self)
        return CFrame.new(0, 0, 0)
    end
    bP.BulkMoveTo = function(self, parts, cframes, bulkMoveMode)
        if type(parts) == "table" and type(cframes) == "table" then
            for i, part in ipairs(parts) do
                if i <= #cframes and part then
                    if not t.property_store[part] then
                        t.property_store[part] = {}
                    end
                    t.property_store[part].CFrame = cframes[i]
                end
            end
        end
        return true
    end
    bP.GetBoundingBox = function(self)
        return CFrame.new(0, 0, 0), Vector3.new(1, 1, 1)
    end
    bP.GetExtentsSize = function(self)
        return Vector3.new(1, 1, 1)
    end
    bP.TranslateBy = function(self, cx)
        local bS = t.registry[bh] or "model"
        at(string.format("%s:TranslateBy(%s)", bS, aZ(cx)))
    end
    bP.LoadAnimation = function(self, cy)
        local bS = t.registry[bh] or "animator"
        local cz = bj("animTrack", false)
        local _ = aW(cz, "animTrack")
        at(string.format("local %s = %s:LoadAnimation(%s)", _, bS, aZ(cy)))
        return cz
    end
    bP.GetPlayingAnimationTracks = function(self)
        return {}
    end
    bP.AdjustSpeed = function(self, cA)
        local bS = t.registry[bh] or "animTrack"
        at(string.format("%s:AdjustSpeed(%s)", bS, aZ(cA)))
    end
    bP.AdjustWeight = function(self, cB, cC)
        local bS = t.registry[bh] or "animTrack"
        if cC then
            at(string.format("%s:AdjustWeight(%s, %s)", bS, aZ(cB), aZ(cC)))
        else
            at(string.format("%s:AdjustWeight(%s)", bS, aZ(cB)))
        end
    end
    bP.Teleport = function(self, cD, cl, cE, cF)
        local bS = t.registry[bh] or "TeleportService"
        at(
            string.format(
                "%s:Teleport(%s, %s%s%s)",
                bS,
                aZ(cD),
                aZ(cl),
                cE and ", " .. aZ(cE) or "",
                cF and ", " .. aZ(cF) or ""
            )
        )
    end
    bP.TeleportToPlaceInstance = function(self, cD, cG, cl)
        local bS = t.registry[bh] or "TeleportService"
        at(string.format("%s:TeleportToPlaceInstance(%s, %s, %s)", bS, aZ(cD), aZ(cG), aZ(cl)))
    end
    bP.PlayLocalSound = function(self, cH)
        local bS = t.registry[bh] or "SoundService"
        at(string.format("%s:PlayLocalSound(%s)", bS, aZ(cH)))
    end
    bP.GetAsync = function(self, cI)
        return "{}"
    end
    bP.PostAsync = function(self, cI, cJ)
        return "{}"
    end
    bP.JSONEncode = function(self, cJ)
        return "{}"
    end
    bP.JSONDecode = function(self, O)
        return {}
    end
    bP.GenerateGUID = function(self, cK)
        return "00000000-0000-0000-0000-000000000000"
    end
    bP.HttpGet = function(self, cI)
        local cL = aE(cI)
        table.insert(t.string_refs, {value = cL, hint = "HTTP URL"})
        t.last_http_url = cL
        return cL
    end
    bP.HttpPost = function(self, cI, cJ, cM)
        local cL = aE(cI)
        table.insert(t.string_refs, {value = cL, hint = "HTTP POST URL"})
        local x = bj("HttpResponse", false)
        local _ = aW(x, "httpResponse")
        local bS = t.registry[bh] or "HttpService"
        at(string.format("local %s = %s:HttpPost(%s, %s, %s)", _, bS, aZ(cI), aZ(cJ), aZ(cM)))
        t.property_store[x] = {Body = "{}", StatusCode = 200, Success = true}
        return x
    end
    bP.AddItem = function(self, cN, cO)
        local bS = t.registry[bh] or "Debris"
        at(string.format("%s:AddItem(%s, %s)", bS, aZ(cN), aZ(cO or 10)))
    end
    bP.AddItems = function(self, cN, cO)
        local bS = t.registry[bh] or "Debris"
        at(string.format("%s:AddItems(%s, %s)", bS, aZ(cN), aZ(cO or 10)))
    end
    bi.__index = function(b2, b4)
        if b4 == F or b4 == "__proxy_id" then
            return rawget(b2, b4)
        end
        if b4 == "PlaceId" or b4 == "GameId" or b4 == "placeId" or b4 == "gameId" then
            return u
        end
        if b4 == "Parent" then
            return t.property_store[bh] and t.property_store[bh].Parent or nil
        end
        if b4 == "Attributes" then
            if not t.property_store[bh] then
                t.property_store[bh] = {}
            end
            if not t.property_store[bh].Attributes then
                t.property_store[bh].Attributes = {}
            end
            return t.property_store[bh].Attributes
        end
        if type(b4) == "string" and (b4:match("^RE/") or b4:match("/")) then
            local remoteProxy = bj(b4, false, bh)
            local remoteName = b4
            local parentObj = bh
            local mt = getmetatable(remoteProxy) or {}
            mt.FireServer = function(self, ...)
                local args = {...}
                local argsStr = {}
                for i, arg in ipairs(args) do
                    table.insert(argsStr, aZ(arg))
                end
                at(string.format("%s:FireServer(%s)", t.registry[remoteProxy] or remoteName, table.concat(argsStr, ", ")))
                table.insert(t.call_graph, {type = "RemoteEvent", name = remoteName, args = args})
            end
            mt.InvokeServer = function(self, ...)
                local args = {...}
                local argsStr = {}
                for i, arg in ipairs(args) do
                    table.insert(argsStr, aZ(arg))
                end
                local result = bj("invokeResult", false)
                aW(result, "result")
                local resultName = t.registry[result] or "result"
                local proxyName = t.registry[remoteProxy] or remoteName
                at(string.format("local %s = %s:InvokeServer(%s)", resultName, proxyName, table.concat(argsStr, ", ")))
                table.insert(t.call_graph, {type = "RemoteFunction", name = remoteName, args = args})
                return result
            end
            mt.FireClient = function(self, player, ...)
                local args = {...}
                local argsStr = {}
                for i, arg in ipairs(args) do
                    table.insert(argsStr, aZ(arg))
                end
                at(string.format("%s:FireClient(%s, %s)", t.registry[remoteProxy] or remoteName, aZ(player), table.concat(argsStr, ", ")))
            end
            mt.FireAllClients = function(self, ...)
                local args = {...}
                local argsStr = {}
                for i, arg in ipairs(args) do
                    table.insert(argsStr, aZ(arg))
                end
                at(string.format("%s:FireAllClients(%s)", t.registry[remoteProxy] or remoteName, table.concat(argsStr, ", ")))
            end
            setmetatable(remoteProxy, mt)
            return remoteProxy
        end
        if b4 == "MouseButton1Click" or b4 == "MouseButton1Down" or b4 == "MouseButton1Up" or 
           b4 == "MouseButton2Click" or b4 == "MouseButton2Down" or b4 == "MouseButton2Up" or
           b4 == "Activated" or b4 == "Deactivated" then
            local signal = bj(b4, false, bh)
            t.registry[signal] = (t.registry[bh] or "object") .. "." .. b4
            local mt = getmetatable(signal) or {}
            mt.Connect = function(self, callback)
                at(string.format("%s:Connect(function()", t.registry[signal]))
                t.indent = t.indent + 1
                if type(callback) == "function" then
                    xpcall(callback, function(err) end)
                end
                while t.pending_iterator do
                    t.indent = t.indent - 1
                    at("end")
                    t.pending_iterator = false
                end
                t.indent = t.indent - 1
                at("end)")
                local conn = bj("connection", false)
                aW(conn, "conn")
                return conn
            end
            mt.Wait = function(self)
                at(string.format("%s:Wait()", t.registry[signal]))
                return true
            end
            setmetatable(signal, mt)
            return signal
        end
        if b4 == "ChildAdded" or b4 == "ChildRemoved" or b4 == "DescendantAdded" or b4 == "DescendantRemoving" then
            local signal = bj(b4, false, bh)
            t.registry[signal] = (t.registry[bh] or "object") .. "." .. b4
            local mt = getmetatable(signal) or {}
            mt.Connect = function(self, callback)
                at(string.format("%s:Connect(function(child)", t.registry[signal]))
                t.indent = t.indent + 1
                if type(callback) == "function" then
                    local fakeChild = bj("child", false)
                    aW(fakeChild, "child")
                    pcall(callback, fakeChild)
                end
                t.indent = t.indent - 1
                at("end)")
                local conn = bj("connection", false)
                aW(conn, "conn")
                return conn
            end
            setmetatable(signal, mt)
            return signal
        end
        if b4 == "JumpRequest" then
            local signal = bj("JumpRequest", false, bh)
            t.registry[signal] = (t.registry[bh] or "UserInputService") .. ".JumpRequest"
            local mt = getmetatable(signal) or {}
            mt.Connect = function(self, callback)
                at("UserInputService.JumpRequest:Connect(function()")
                t.indent = t.indent + 1
                if type(callback) == "function" then
                    pcall(callback)
                end
                t.indent = t.indent - 1
                at("end)")
                local conn = bj("connection", false)
                aW(conn, "conn")
                return conn
            end
            setmetatable(signal, mt)
            return signal
        end
        if b4 == "CharacterAdded" or b4 == "CharacterRemoving" then
            local signal = bj(b4, false, bh)
            t.registry[signal] = (t.registry[bh] or "Players.LocalPlayer") .. "." .. b4
            local mt = getmetatable(signal) or {}
            mt.Connect = function(self, callback)
                at(string.format("%s:Connect(function(character)", t.registry[signal]))
                t.indent = t.indent + 1
                if type(callback) == "function" then
                    local fakeChar = bj("Character", false)
                    aW(fakeChar, "character")
                    pcall(callback, fakeChar)
                end
                t.indent = t.indent - 1
                at("end)")
                local conn = bj("connection", false)
                aW(conn, "conn")
                return conn
            end
            setmetatable(signal, mt)
            return signal
        end
        local bS = t.registry[bh] or aT or "object"
        local cP = aE(b4)
        if t.property_store[bh] and t.property_store[bh][b4] ~= nil then
            return t.property_store[bh][b4]
        end
        if bP[cP] then
            local cQ, cR = bg()
            t.registry[cQ] = bS .. "." .. cP
            cR.__call = function(W, ...)
                local bA = {...}
                if bA[1] == bh or (G(bA[1]) and bA[1] ~= cQ) then
                    table.remove(bA, 1)
                end
                return bP[cP](bh, table.unpack(bA))
            end
            cR.__index = function(W, cS)
                if cS == F or cS == "__proxy_id" then
                    return rawget(cQ, cS)
                end
                return bj(cS, false, cQ)
            end
            cR.__tostring = function()
                return bS .. ":" .. cP
            end
            return cQ
        end
        if bS == "fenv" or bS == "getgenv" or bS == "_G" then
            if b4 == "game" then
                return game
            end
            if b4 == "workspace" then
                return workspace
            end
            if b4 == "Gravity" then
                return 196.2
            end
            if b4 == "script" then
                return script
            end
            if b4 == "Enum" then
                return Enum
            end
            if _G[b4] ~= nil then
                return _G[b4]
            end
            return nil
        end
        if b4 == "EnumType" then
            local enum_name = t.registry[bh]:match("(Enum%.[^.]+)%.")
            if enum_name then
                return rawget(_G, enum_name) or Enum
            end
            return Enum
        end
        if b4 == "Parent" then
            return t.parent_map[bh] or bj("Parent", false)
        end
        if b4 == "Name" then
            return aT or "Object"
        end
        if b4 == "ClassName" then
            return aT or "Instance"
        end
        if b4 == "LocalPlayer" then
            local cT = bj("LocalPlayer", false, bh)
            local _ = aW(cT, "LocalPlayer")
            at(string.format("local %s = %s.LocalPlayer", _, bS))
            return cT
        end
        if b4 == "MembershipType" then
            local mt = bj("Enum.MembershipType.None", false)
            t.registry[mt] = "Enum.MembershipType.None"
            if not t.property_store[mt] then
                t.property_store[mt] = {}
            end
            t.property_store[mt].Name = "None"
            t.property_store[mt].Value = 0
            return mt
        end
        if b4 == "PlayerGui" then
            return bj("PlayerGui", false, bh)
        end
        if b4 == "Backpack" then
            return bj("Backpack", false, bh)
        end
        if b4 == "PlayerScripts" then
            return bj("PlayerScripts", false, bh)
        end
        if b4 == "UserId" then
            return 1262536232
        end
        if b4 == "DisplayName" then
            return "Evade12276"
        end
        if b4 == "AccountAge" then
            return 1156
        end
        if b4 == "Team" then
            return bj("Team", true, bh)
        end
        if b4 == "TeamColor" then
            return BrickColor.new("White")
        end
        if b4 == "Character" then
            return bj("Character", true, bh)
        end
        if b4 == "Humanoid" then
            local cU = bj("Humanoid", true, bh)
            t.property_store[cU] = {Health = 100, MaxHealth = 100, WalkSpeed = 16, JumpPower = 50, JumpHeight = 7.2}
            return cU
        end
        if b4 == "HumanoidRootPart" or b4 == "PrimaryPart" or b4 == "RootPart" then
            local cV = bj("HumanoidRootPart", false, bh)
            t.property_store[cV] = {Position = Vector3.new(0, 0, 0), CFrame = CFrame.new(0, 5, 0)}
            return cV
        end
        local cW = {
            "Head", "Torso", "UpperTorso", "LowerTorso", "RightArm", "LeftArm",
            "RightLeg", "LeftLeg", "RightHand", "LeftHand", "RightFoot", "LeftFoot"
        }
        for W, cr in ipairs(cW) do
            if b4 == cr then
                return bj(b4, false, bh)
            end
        end
        if b4 == "Animator" then
            return bj("Animator", false, bh)
        end
        if b4 == "CurrentCamera" or b4 == "Camera" then
            local cX = bj("Camera", false, bh)
            t.property_store[cX] = {
                CFrame = CFrame.new(0, 10, 0),
                FieldOfView = 70,
                ViewportSize = Vector2.new(1920, 1080)
            }
            return cX
        end
        if bS == "Camera" then
            if b4 == "ViewportSize" then
                return Vector2.new(1920, 1080)
            end
            if b4 == "ViewportSize.X" then
                return 1920
            end
            if b4 == "ViewportSize.Y" then
                return 1080
            end
        end
        if b4 == "Ambient" then
            local ambientVal = Color3.new(0.5, 0.5, 0.5)
            if t.property_store[bh] and t.property_store[bh].Ambient then
                ambientVal = t.property_store[bh].Ambient
            end
            return ambientVal
        end
        if b4 == "FogEnd" then
            if t.property_store[bh] and t.property_store[bh].FogEnd then
                return t.property_store[bh].FogEnd
            end
            return 100000
        end
        if b4 == "FogStart" then
            if t.property_store[bh] and t.property_store[bh].FogStart then
                return t.property_store[bh].FogStart
            end
            return 0
        end
        if b4 == "FogColor" then
            if t.property_store[bh] and t.property_store[bh].FogColor then
                return t.property_store[bh].FogColor
            end
            return Color3.new(0.5, 0.5, 0.5)
        end
        if b4 == "OutdoorAmbient" then
            return Color3.new(0.5, 0.5, 0.5)
        end
        if b4 == "ColorShift_Top" then
            return Color3.new(0, 0, 0)
        end
        if b4 == "ColorShift_Bottom" then
            return Color3.new(0, 0, 0)
        end
        if b4 == "GlobalShadows" then
            return true
        end
        if b4 == "ClockTime" then
            return 14
        end
        if b4 == "GeographicLatitude" then
            return 41.9
        end
        if b4 == "CameraType" then
            return bj("Enum.CameraType.Custom", false)
        end
        if b4 == "CameraSubject" then
            return bj("Humanoid", false, bh)
        end
        local cY = {
            Health = 100, MaxHealth = 100, WalkSpeed = 16, JumpPower = 50,
            JumpHeight = 7.2, HipHeight = 2, Transparency = 0, Mass = 1,
            Value = 0, TimePosition = 0, TimeLength = 1, Volume = 0.5,
            PlaybackSpeed = 1, Brightness = 1, Range = 60, Angle = 90,
            FieldOfView = 70, Size = 1, Thickness = 1, ZIndex = 1,
            LayoutOrder = 0, Ambient = Color3.new(0.5, 0.5, 0.5),
            FogEnd = 100000, FogStart = 0, FogColor = Color3.new(0.5, 0.5, 0.5),
        }
        if cY[b4] then
            return bl(cY[b4])
        end
        local cZ = {
            Visible = true, Enabled = true, Anchored = false, CanCollide = true,
            Locked = false, Active = true, Draggable = false, Modal = false,
            Playing = false, Looped = false, IsPlaying = false, AutoPlay = false,
            Archivable = true, ClipsDescendants = false, RichText = false,
            TextWrapped = false, TextScaled = false, PlatformStand = false,
            AutoRotate = true, Sit = false
        }
        if cZ[b4] ~= nil then
            return cZ[b4]
        end
        if b4 == "AbsoluteSize" or b4 == "ViewportSize" then
            return Vector2.new(1920, 1080)
        end
        if b4 == "AbsolutePosition" then
            return Vector2.new(0, 0)
        end
        if b4 == "Position" then
            if aT and (aT:match("Part") or aT:match("Model") or aT:match("Character") or aT:match("Root")) then
                return Vector3.new(0, 5, 0)
            end
            return UDim2.new(0, 0, 0, 0)
        end
        if b4 == "Size" then
            if aT and aT:match("Part") then
                return Vector3.new(4, 1, 2)
            end
            return UDim2.new(1, 0, 1, 0)
        end
        if b4 == "CFrame" then
            return CFrame.new(0, 5, 0)
        end
        if b4 == "Velocity" or b4 == "AssemblyLinearVelocity" then
            local velProxy = bj("Vector3", false)
            t.registry[velProxy] = (t.registry[bh] or "part") .. ".Velocity"
            local velMt = getmetatable(velProxy) or {}
            velMt.__index = function(self, key)
                if key == "X" then return 0
                elseif key == "Y" then return 0
                elseif key == "Z" then return 0 end
                return nil
            end
            velMt.__newindex = function(self, key, value)
                at(string.format("%s.Velocity.%s = %s", t.registry[bh] or "part", key, aZ(value)))
            end
            setmetatable(velProxy, velMt)
            return velProxy
        end
        if b4 == "RotVelocity" or b4 == "AssemblyAngularVelocity" then
            return Vector3.new(0, 0, 0)
        end
        if b4 == "Orientation" or b4 == "Rotation" then
            return Vector3.new(0, 0, 0)
        end
        if b4 == "LookVector" then
            return Vector3.new(0, 0, -1)
        end
        if b4 == "RightVector" then
            return Vector3.new(1, 0, 0)
        end
        if b4 == "UpVector" then
            return Vector3.new(0, 1, 0)
        end
        if b4 == "Color" or b4 == "Color3" or b4 == "BackgroundColor3" or b4 == "BorderColor3" or 
           b4 == "TextColor3" or b4 == "PlaceholderColor3" or b4 == "ImageColor3" then
            return Color3.new(1, 1, 1)
        end
        if b4 == "BrickColor" then
            return BrickColor.new("Medium stone grey")
        end
        if b4 == "Material" then
            return bj("Enum.Material.Plastic", false)
        end
        if b4 == "Hit" then
            return CFrame.new(0, 0, -10)
        end
        if b4 == "Origin" then
            return CFrame.new(0, 5, 0)
        end
        if b4 == "Target" then
            return bj("Target", false, bh)
        end
        if b4 == "X" or b4 == "Y" then
            return 0
        end
        if b4 == "UnitRay" then
            return Ray.new(Vector3.new(0, 5, 0), Vector3.new(0, 0, -1))
        end
        if b4 == "ViewSizeX" then
            return 1920
        end
        if b4 == "ViewSizeY" then
            return 1080
        end
        if b4 == "Text" or b4 == "PlaceholderText" or b4 == "ContentText" or b4 == "Value" then
            if s then
                return s
            end
            if b4 == "Value" then
                return "input"
            end
            return ""
        end
        if b4 == "TextBounds" then
            return Vector2.new(0, 0)
        end
        if b4 == "Font" then
            return bj("Enum.Font.SourceSans", false)
        end
        if b4 == "TextSize" then
            return 14
        end
        if b4 == "Image" or b4 == "ImageContent" then
            return ""
        end
        local c_ = {
            "Changed", "ChildAdded", "ChildRemoved", "DescendantAdded", "DescendantRemoving",
            "Touched", "TouchEnded", "InputBegan", "InputEnded", "InputChanged",
            "MouseButton1Click", "MouseButton1Down", "MouseButton1Up", "MouseButton2Click",
            "MouseButton2Down", "MouseButton2Up", "MouseEnter", "MouseLeave", "MouseMoved",
            "MouseWheelForward", "MouseWheelBackward", "Activated", "Deactivated", "FocusLost",
            "FocusGained", "Focused", "Heartbeat", "RenderStepped", "Stepped", "CharacterAdded",
            "CharacterRemoving", "CharacterAppearanceLoaded", "PlayerAdded", "PlayerRemoving",
            "AncestryChanged", "AttributeChanged", "Died", "FreeFalling", "GettingUp", "Jumping",
            "Running", "Seated", "Swimming", "StateChanged", "HealthChanged", "MoveToFinished",
            "OnClientEvent", "OnServerEvent", "OnClientInvoke", "OnServerInvoke", "Completed",
            "DidLoop", "Stopped", "Button1Down", "Button1Up", "Button2Down", "Button2Up",
            "Idle", "Move", "TextChanged", "ReturnPressedFromOnScreenKeyboard", "Triggered", "TriggerEnded"
        }
        for W, d0 in ipairs(c_) do
            if b4 == d0 then
                local cg = bj(bS .. "." .. b4, false, bh)
                t.registry[cg] = bS .. "." .. b4
                return cg
            end
        end
        if bS:match("^Enum") then
            local d1 = bS .. "." .. cP
            local d2 = bj(d1, false)
            t.registry[d2] = d1
            return d2
        end
        return bk(cP, bh)
    end
    if cP == "Completed" then
        if not bP._completedSignal then
            bP._completedSignal = bP._getCompletedSignal(bh)
        end
        return bP._completedSignal
    end
    bi.__newindex = function(b2, b4, b5)
        if b4 == F or b4 == "__proxy_id" then
            rawset(b2, b4, b5)
            return
        end
        local bS = t.registry[bh] or aT or "object"
        local cP = aE(b4)
        if bS == "Sound" and b4 == "PlaybackLoudness" then
            error("Attempt to set readonly property PlaybackLoudness", 2)
        end
        t.property_store[bh] = t.property_store[bh] or {}
        if b4 == "Parent" then
            local old_parent = t.property_store[bh].Parent
            if old_parent and t.property_store[old_parent] and t.property_store[old_parent].Children then
                for i, child in ipairs(t.property_store[old_parent].Children) do
                    if child == bh then
                        table.remove(t.property_store[old_parent].Children, i)
                        break
                    end
                end
            end
            t.property_store[bh].Parent = b5
            if b5 and G(b5) then
                if not t.property_store[b5] then
                    t.property_store[b5] = {}
                end
                if not t.property_store[b5].Children then
                    t.property_store[b5].Children = {}
                end
                local already_exists = false
                for _, child in ipairs(t.property_store[b5].Children) do
                    if child == bh then
                        already_exists = true
                        break
                    end
                end
                if not already_exists then
                    table.insert(t.property_store[b5].Children, bh)
                end
                t.parent_map[bh] = b5
            end
            at(string.format("%s.Parent = %s", bS, aZ(b5)))
        else
            t.property_store[bh][b4] = b5
            at(string.format("%s.%s = %s", bS, cP, aZ(b5)))
        end
    end
    if bS == "Lighting" then
        if b4 == "Ambient" or b4 == "OutdoorAmbient" or b4 == "ColorShift_Top" or b4 == "ColorShift_Bottom" then
            t.property_store[bh][b4] = b5
            at(string.format("%s.%s = %s", bS, cP, aZ(b5)))
            return
        end
    end
    bi.__call = function(b2, ...)
        local bS = t.registry[bh] or aT or "func"
        if bS == "fenv" or bS == "getgenv" or bS:match("env") then
            return bh
        end
        local bA = {...}
        local c5 = {}
        for W, b5 in ipairs(bA) do
            table.insert(c5, aZ(b5))
        end
        local z = bj("result", false)
        local _ = aW(z, "result")
        at(string.format("local %s = %s(%s)", _, bS, table.concat(c5, ", ")))
        return z
    end
    local function d3(d4)
        local function d5(bo, aa)
            local bh, bi = bg()
            local d6 = "0"
            if bo ~= nil then
                d6 = t.registry[bo] or aZ(bo)
            end
            local d7 = "0"
            if aa ~= nil then
                d7 = t.registry[aa] or aZ(aa)
            end
            local d8 = "(" .. d6 .. " " .. d4 .. " " .. d7 .. ")"
            t.registry[bh] = d8
            bi.__tostring = function()
                return d8
            end
            bi.__call = function()
                return bh
            end
            bi.__index = function(W, b4)
                if b4 == F or b4 == "__proxy_id" then
                    return rawget(bh, b4)
                end
                return bj(d8 .. "." .. aE(b4), false)
            end
            bi.__add = d3("+")
            bi.__sub = d3("-")
            bi.__mul = d3("*")
            bi.__div = d3("/")
            bi.__mod = d3("%")
            bi.__pow = d3("^")
            bi.__concat = d3("..")
            bi.__eq = function()
                return false
            end
            bi.__lt = function()
                return false
            end
            bi.__le = function()
                return false
            end
            return bh
        end
        return d5
    end
    bi.__add = d3("+")
    bi.__sub = d3("-")
    bi.__mul = d3("*")
    bi.__div = d3("/")
    bi.__mod = d3("%")
    bi.__pow = d3("^")
    bi.__concat = d3("..")
    bi.__eq = function()
        return false
    end
    bi.__lt = function()
        return false
    end
    bi.__le = function()
        return false
    end
    bi.__unm = function(bo)
        local z, d9 = bg()
        t.registry[z] = "(-" .. (t.registry[bo] or aZ(bo)) .. ")"
        d9.__tostring = function()
            return t.registry[z]
        end
        return z
    end
    bi.__len = function()
        return 0
    end
    bi.__tostring = function()
        return t.registry[bh] or aT or "Object"
    end
    bi.__pairs = function()
        return function()
            return nil
        end, bh, nil
    end
    bi.__ipairs = bi.__pairs
    return bh
end
local function da(am, db)
    local dc = {}
    local dd = {}
    dd.__index = function(b2, b4)
        if b4 == "new" or (db and db[b4]) then
            return function(...)
                local bA = {...}
                local c5 = {}
                for W, b5 in ipairs(bA) do
                    table.insert(c5, aZ(b5))
                end
                local d8 = am .. "." .. b4 .. "(" .. table.concat(c5, ", ") .. ")"
                local bh, de = bg()
                t.registry[bh] = d8
                de.__tostring = function()
                    return d8
                end
                de.__index = function(W, bG)
                    if bG == F or bG == "__proxy_id" then
                        return rawget(bh, bG)
                    end
                    if bG == "X" or bG == "Y" or bG == "Z" or bG == "W" then
                        return 0
                    end
                    if bG == "Magnitude" then
                        return 0
                    end
                    if bG == "Unit" then
                        return bh
                    end
                    if bG == "Position" then
                        return bh
                    end
                    if bG == "CFrame" then
                        return bh
                    end
                    if bG == "LookVector" or bG == "RightVector" or bG == "UpVector" then
                        return bh
                    end
                    if bG == "Rotation" then
                        return bh
                    end
                    if bG == "R" or bG == "G" or bG == "B" then
                        return 1
                    end
                    if bG == "Width" or bG == "Height" then
                        return UDim.new(0, 0)
                    end
                    if bG == "Min" or bG == "Max" then
                        return 0
                    end
                    if bG == "Scale" or bG == "Offset" then
                        return 0
                    end
                    if bG == "p" then
                        return bh
                    end
                    return 0
                end
                local function df(Z)
                    return function(bo, aa)
                        local dg, dh = bg()
                        local O = "(" .. (t.registry[bo] or aZ(bo)) .. " " .. Z .. " " .. (t.registry[aa] or aZ(aa)) .. ")"
                        t.registry[dg] = O
                        dh.__tostring = function()
                            return O
                        end
                        dh.__index = de.__index
                        dh.__add = df("+")
                        dh.__sub = df("-")
                        dh.__mul = df("*")
                        dh.__div = df("/")
                        return dg
                    end
                end
                de.__add = df("+")
                de.__sub = df("-")
                de.__mul = df("*")
                de.__div = df("/")
                de.__unm = function(bo)
                    local dg, dh = bg()
                    t.registry[dg] = "(-" .. (t.registry[bo] or aZ(bo)) .. ")"
                    dh.__tostring = function()
                        return t.registry[dg]
                    end
                    return dg
                end
                de.__eq = function()
                    return false
                end
                return bh
            end
        end
        return nil
    end
    dd.__call = function(b2, ...)
        return b2.new(...)
    end
    return setmetatable(dc, dd)
end
Vector3 = da("Vector3", {new = true, zero = true, one = true})
Vector2 = da("Vector2", {new = true, zero = true, one = true})
UDim = da("UDim", {new = true})
UDim2 = da("UDim2", {new = true, fromScale = true, fromOffset = true})
CFrame = da("CFrame", {
    new = true, Angles = true, lookAt = true, fromEulerAnglesXYZ = true,
    fromEulerAnglesYXZ = true, fromAxisAngle = true, fromMatrix = true,
    fromOrientation = true, identity = true
})
Color3 = da("Color3", {new = true, fromRGB = true, fromHSV = true, fromHex = true})
BrickColor = da("BrickColor", {
    new = true, random = true, White = true, Black = true, Red = true,
    Blue = true, Green = true, Yellow = true, palette = true
})
TweenInfo = function(duration, easeStyle, easeDirection, repeatCount, reverses, delayTime)
    local proxy = da("TweenInfo", {new = true})("new", duration, easeStyle, easeDirection, repeatCount, reverses, delayTime)
    if proxy and type(proxy) == "table" then
        proxy._duration = duration or 0.1
    end
    return proxy
end
Rect = da("Rect", {new = true})
Region3 = da("Region3", {new = true})
Region3int16 = da("Region3int16", {new = true})
Ray = da("Ray", {new = true})
NumberRange = da("NumberRange", {new = true})
NumberSequence = da("NumberSequence", {new = true})
NumberSequenceKeypoint = da("NumberSequenceKeypoint", {new = true})
ColorSequence = da("ColorSequence", {new = true})
ColorSequenceKeypoint = da("ColorSequenceKeypoint", {new = true})
PhysicalProperties = da("PhysicalProperties", {new = true})
Font = da("Font", {new = true, fromEnum = true, fromName = true, fromId = true})
RaycastParams = da("RaycastParams", {new = true})
OverlapParams = da("OverlapParams", {new = true})
PathWaypoint = da("PathWaypoint", {new = true})
Axes = da("Axes", {new = true})
Faces = da("Faces", {new = true})
Vector3int16 = da("Vector3int16", {new = true})
Vector2int16 = da("Vector2int16", {new = true})
CatalogSearchParams = da("CatalogSearchParams", {new = true})
DateTime = da("DateTime", {now = true, fromUnixTimestamp = true, fromUnixTimestampMillis = true, fromIsoDate = true})
Random = {new = function(di)
    local x = {}
    function x:NextNumber(dj, dk)
        return (dj or 0) + 0.5 * ((dk or 1) - (dj or 0))
    end
    function x:NextInteger(dj, dk)
        return math.floor((dj or 1) + 0.5 * ((dk or 100) - (dj or 1)))
    end
    function x:NextUnitVector()
        return Vector3.new(0.577, 0.577, 0.577)
    end
    function x:Shuffle(dl)
        return dl
    end
    function x:Clone()
        return Random.new()
    end
    return x
end}
setmetatable(Random, {__call = function(b2, di) return b2.new(di) end})
Enum = bj("Enum", true)
local dm = a.getmetatable(Enum)
local old_enum_index = dm.__index

-- FIX 1: Tambahkan GetEnums() method
-- Support kedua cara: sebagai method dan sebagai function
dm.GetEnums = function(self)
    local enums = {}
    for k, v in pairs(self) do
        if type(k) == "string" and k ~= "GetEnums" and k ~= "GetEnumItems" and type(v) ~= "function" then
            table.insert(enums, v)
        end
    end
    return enums
end

-- Juga tambahkan di global Enum
function Enum.GetEnums(self)
    return dm.GetEnums(self)
end

dm.__index = function(b2, b4)
    if b4 == "GetEnumItems" then
        return function(self)
            local items = {}
            for k, v in pairs(self) do
                if k ~= "GetEnumItems" and type(v) ~= "function" then
                    if G(v) then
                        if not t.property_store[v] then
                            t.property_store[v] = {}
                        end
                        t.property_store[v].Name = t.property_store[v].Name or tostring(k)
                        t.property_store[v].Value = t.property_store[v].Value or 1
                        table.insert(items, v)
                    end
                end
            end
            return items
        end
    end
    if b4 == "GetEnums" then
        return dm.GetEnums
    end
    if b4 == F or b4 == "__proxy_id" then
        return rawget(b2, b4)
    end
    local dn = bj("Enum." .. aE(b4), false)
    t.registry[dn] = "Enum." .. aE(b4)
    return dn
end

-- FIX 2: Tambah Enum.Font items
local font_enum = bj("Enum.Font", false)
t.property_store[font_enum] = t.property_store[font_enum] or {}
local font_items = {
    {Name = "Gotham", Value = 1, Family = "Gotham", Weight = 400},
    {Name = "GothamBold", Value = 2, Family = "Gotham", Weight = 700},
    {Name = "GothamMedium", Value = 3, Family = "Gotham", Weight = 500},
    {Name = "SourceSans", Value = 4, Family = "Source Sans", Weight = 400},
    {Name = "SourceSansBold", Value = 5, Family = "Source Sans", Weight = 700},
}
for _, item in ipairs(font_items) do
    local obj = bj("Enum.Font." .. item.Name, false)
    t.registry[obj] = "Enum.Font." .. item.Name
    if not t.property_store[obj] then t.property_store[obj] = {} end
    t.property_store[obj].Name = item.Name
    t.property_store[obj].Value = item.Value
    t.property_store[obj].Family = item.Family
    t.property_store[obj].Weight = item.Weight
    font_enum[item.Name] = obj
    font_enum[item.Value] = obj
end

-- FIX 3: Tambah Enum.FontWeight
local fontweight_enum = bj("Enum.FontWeight", false)
local fontweight_items = {
    {Name = "Regular", Value = 400},
    {Name = "Medium", Value = 500},
    {Name = "Bold", Value = 700},
}
for _, item in ipairs(fontweight_items) do
    local obj = bj("Enum.FontWeight." .. item.Name, false)
    t.registry[obj] = "Enum.FontWeight." .. item.Name
    if not t.property_store[obj] then t.property_store[obj] = {} end
    t.property_store[obj].Name = item.Name
    t.property_store[obj].Value = item.Value
    fontweight_enum[item.Name] = obj
    fontweight_enum[item.Value] = obj
end

-- FIX 4: Tambah Enum.KeyInterpolationMode
local interp_enum = bj("Enum.KeyInterpolationMode", false)
t.property_store[interp_enum] = t.property_store[interp_enum] or {}
local interp_items = {
    {Name = "Linear", Value = 0},
    {Name = "Constant", Value = 1},
    {Name = "Cubic", Value = 2},
}
for _, item in ipairs(interp_items) do
    local obj = bj("Enum.KeyInterpolationMode." .. item.Name, false)
    t.registry[obj] = "Enum.KeyInterpolationMode." .. item.Name
    if not t.property_store[obj] then t.property_store[obj] = {} end
    t.property_store[obj].Name = item.Name
    t.property_store[obj].Value = item.Value
    interp_enum[item.Name] = obj
    interp_enum[item.Value] = obj
end

-- FIX 5: Font.fromEnum() method
local font_mt = getmetatable(font_enum) or {}
font_mt.fromEnum = function(self, font_enum_item)
    if type(font_enum_item) == "table" and t.registry[font_enum_item] then
        local font_proxy = bj("Font", false)
        aW(font_proxy, "font")
        if not t.property_store[font_proxy] then t.property_store[font_proxy] = {} end
        t.property_store[font_proxy].Family = t.property_store[font_enum_item].Family or "Unknown"
        t.property_store[font_proxy].Weight = t.property_store[font_enum_item].Weight or 400
        t.property_store[font_proxy].Name = t.property_store[font_enum_item].Name or "Unknown"
        return font_proxy
    end
    return bj("Font", false)
end
setmetatable(font_enum, font_mt)

-- FIX 6: FloatCurve dan FloatCurveKey
local FloatCurveKey = {
    new = function(time, value, interpolation)
        local key = bj("FloatCurveKey", false)
        aW(key, "floatKey")
        if not t.property_store[key] then t.property_store[key] = {} end
        t.property_store[key].Time = time or 0
        t.property_store[key].Value = value or 0
        t.property_store[key].Interpolation = interpolation or interp_enum.Linear
        return key
    end
}

local FloatCurve = {
    new = function()
        local curve = bj("FloatCurve", false)
        aW(curve, "floatCurve")
        if not t.property_store[curve] then t.property_store[curve] = {} end
        t.property_store[curve]._keys = {}
        return curve
    end
}

local floatcurve_mt = {}
floatcurve_mt.InsertKey = function(self, key)
    if not t.property_store[self] then t.property_store[self] = {} end
    if not t.property_store[self]._keys then t.property_store[self]._keys = {} end
    table.insert(t.property_store[self]._keys, key)
    return #t.property_store[self]._keys
end

floatcurve_mt.GetKeyAtIndex = function(self, index)
    if not t.property_store[self] or not t.property_store[self]._keys then return nil end
    return t.property_store[self]._keys[index]
end

floatcurve_mt.GetValueAtTime = function(self, time)
    if not t.property_store[self] or not t.property_store[self]._keys then return 0 end
    local keys = t.property_store[self]._keys
    if #keys == 0 then return 0 end
    if time <= keys[1].Time then return keys[1].Value end
    if time >= keys[#keys].Time then return keys[#keys].Value end
    
    for i = 1, #keys - 1 do
        local k1 = keys[i]
        local k2 = keys[i + 1]
        if time >= k1.Time and time <= k2.Time then
            local t_frac = (time - k1.Time) / (k2.Time - k1.Time)
            local interp = k1.Interpolation
            if interp == interp_enum.Linear then
                return k1.Value + (k2.Value - k1.Value) * t_frac
            elseif interp == interp_enum.Constant then
                return k1.Value
            else
                return k1.Value + (k2.Value - k1.Value) * (3*t_frac*t_frac - 2*t_frac*t_frac*t_frac)
            end
        end
    end
    return 0
end

floatcurve_mt.Destroy = function(self) end

setmetatable(FloatCurve, {__call = function(self) return FloatCurve.new() end})
_G.FloatCurve = FloatCurve
_G.FloatCurveKey = FloatCurveKey
setmetatable(_G.FloatCurve, {__call = function(_, ...) return FloatCurve.new(...) end})
setmetatable(_G.FloatCurveKey, {__call = function(_, ...) return FloatCurveKey.new(...) end})
Instance = {new = function(bX, bS)
    local bY = aE(bX)
    local x = bj(bY, false)
    local _ = aW(x, bY)
    if bS then
        local dp = t.registry[bS] or aZ(bS)
        at(string.format("local %s = Instance.new(%s, %s)", _, aH(bY), dp))
        t.parent_map[x] = bS
        if not t.property_store[x] then
            t.property_store[x] = {}
        end
        t.property_store[x].Parent = bS
        if not t.property_store[bS] then
            t.property_store[bS] = {}
        end
        if not t.property_store[bS].Children then
            t.property_store[bS].Children = {}
        end
        table.insert(t.property_store[bS].Children, x)
    else
        at(string.format("local %s = Instance.new(%s)", _, aH(bY)))
    end
    return x
end}
game = bj("game", true)
workspace = bj("workspace", true)
if not t.property_store[workspace] then
    t.property_store[workspace] = {}
end
t.property_store[workspace].ClassName = "Workspace"
t.property_store[workspace].Name = "Workspace"
script = bj("script", true)
t.property_store[script] = {Name = "DumpedScript", Parent = game, ClassName = "LocalScript"}
t.property_store[game] = t.property_store[game] or {}
t.property_store[game].JobId = "00000000-0000-0000-0000-000000000000"
t.property_store[game].PlaceVersion = 1
t.property_store[game].CreatorId = 1
t.property_store[game].CreatorType = Enum.CreatorType.User
t.property_store[game].Name = "Game"
t.property_store[game].ClassName = "DataModel"
if not t.property_store[game] then
    t.property_store[game] = {}
end
t.property_store[game].ClassName = "DataModel"
t.property_store[game].Name = "Game"

-- workspace
if t.property_store[game] then
    if not t.property_store[game].Children then
        t.property_store[game].Children = {}
    end
    local workspace_exists = false
    for _, child in ipairs(t.property_store[game].Children) do
        if child == workspace then
            workspace_exists = true
            break
        end
    end
    if not workspace_exists then
        table.insert(t.property_store[game].Children, workspace)
    end
end
t.parent_map[workspace] = game

-- RBXAnalyticsService
local analyticsService = bj("RBXAnalyticsService", true)
t.property_store[analyticsService] = {}
t.property_store[analyticsService].Name = "RBXAnalyticsService"
t.property_store[analyticsService].ClassName = "RBXAnalyticsService"
local analyticsMt = getmetatable(analyticsService) or {}
analyticsMt.LogEvent = function(self, eventName, parameters)
    at(string.format("%s:LogEvent(%s, %s)", t.registry[analyticsService] or "RBXAnalyticsService", aH(eventName), aZ(parameters or {})))
    table.insert(t.call_graph, {type = "AnalyticsEvent", name = "LogEvent", eventName = eventName, parameters = parameters})
    return true
end
analyticsMt.LogCustomEvent = function(self, eventName, eventData)
    at(string.format("%s:LogCustomEvent(%s, %s)", t.registry[analyticsService] or "RBXAnalyticsService", aH(eventName), aH(eventData or "")))
    return true
end
analyticsMt.LogSessionStart = function(self, sessionData)
    at(string.format("%s:LogSessionStart(%s)", t.registry[analyticsService] or "RBXAnalyticsService", aZ(sessionData or {})))
    return true
end
analyticsMt.LogSessionEnd = function(self, sessionData)
    at(string.format("%s:LogSessionEnd(%s)", t.registry[analyticsService] or "RBXAnalyticsService", aZ(sessionData or {})))
    return true
end
analyticsMt.GetAnalyticsData = function(self)
    local proxy = bj("AnalyticsData", false)
    at(string.format("local %s = %s:GetAnalyticsData()", t.registry[proxy] or "analyticsData", t.registry[analyticsService] or "RBXAnalyticsService"))
    return proxy
end
analyticsMt.SetUserId = function(self, userId)
    at(string.format("%s:SetUserId(%s)", t.registry[analyticsService] or "RBXAnalyticsService", aZ(userId)))
    return true
end
analyticsMt.SetSessionId = function(self, sessionId)
    at(string.format("%s:SetSessionId(%s)", t.registry[analyticsService] or "RBXAnalyticsService", aH(sessionId)))
    return true
end
analyticsMt.Flush = function(self)
    at(string.format("%s:Flush()", t.registry[analyticsService] or "RBXAnalyticsService"))
    return true
end
setmetatable(analyticsService, analyticsMt)
_G.RBXAnalyticsService = analyticsService
game:GetService("RBXAnalyticsService")
Lighting = bj("Lighting", true)
t.property_store[Lighting] = {
    Ambient = Color3.new(0.5, 0.5, 0.5), OutdoorAmbient = Color3.new(0.5, 0.5, 0.5),
    ColorShift_Top = Color3.new(0, 0, 0), ColorShift_Bottom = Color3.new(0, 0, 0),
    GlobalShadows = true, ClockTime = 14, GeographicLatitude = 41.9, Brightness = 1,
    Technology = "ShadowMap", FogColor = Color3.new(0.5, 0.5, 0.5), FogEnd = 100000, FogStart = 0
}
_G.Lighting = Lighting
task = {
    _add_heartbeat = function(fn)
        if type(fn) == "function" then
            table.insert(_G.__heartbeat_callbacks, fn)
        end
    end,
    wait = function(dq)
        for _, cb in ipairs(_G.__heartbeat_callbacks or {}) do
            pcall(cb, dq or 0.016)
        end
        t.wait_calls = (t.wait_calls or 0) + 1
        if t.wait_calls > r.TASK_WAIT_LIMIT then
            at("error('lunr: task.wait infinite loop detected and stopped')")
            error('lunr: task.wait infinite loop detected and stopped')
        end
        if dq then
            at(string.format("task.wait(%s)", aZ(dq)))
        else
            at("task.wait()")
        end
        return dq or 0.03, p.clock()
    end,
    spawn = function(dr, ...)
        if type(dr) ~= "function" and type(dr) ~= "thread" then
            error("invalid argument #1 to 'spawn' (function or thread expected)", 2)
        end
        local bA = {...}
        local thread = coroutine.create(function() return true end)
        at("task.spawn(function()")
        t.indent = t.indent + 1
        if j(dr) == "function" then
            local success, result = pcall(dr, table.unpack(bA or {}))
            if not success then
                at("-- Error in task.spawn: " .. tostring(result))
            end
        elseif j(dr) == "thread" then
            pcall(coroutine.resume, dr)
        end
        while t.pending_iterator do
            t.indent = t.indent - 1
            at("end")
            t.pending_iterator = false
        end
        t.indent = t.indent - 1
        at("end)")
        return thread
    end,
    delay = function(dq, dr, ...)
        local bA = {...}
        at(string.format("task.delay(%s, function()", aZ(dq or 0)))
        t.indent = t.indent + 1
        if j(dr) == "function" and (dq or 0) < 1 then
            xpcall(function() dr(table.unpack(bA or {})) end, function(ds) end)
        end
        while t.pending_iterator do
            t.indent = t.indent - 1
            at("end")
            t.pending_iterator = false
        end
        t.indent = t.indent - 1
        at("end)")
    end,
    defer = function(dr, ...)
        local bA = {...}
        at("task.defer(function()")
        t.indent = t.indent + 1
        if j(dr) == "function" then
            xpcall(function() dr(table.unpack(bA or {})) end, function(ds) end)
        end
        while t.pending_iterator do
            t.indent = t.indent - 1
            at("end")
            t.pending_iterator = false
        end
        t.indent = t.indent - 1
        at("end)")
    end,
    cancel = function(dt)
        at("task.cancel(thread)")
    end,
    synchronize = function()
        at("task.synchronize()")
    end,
    desynchronize = function()
        at("task.desynchronize()")
    end
}
wait = function(dq)
    t.wait_calls = (t.wait_calls or 0) + 1
    if t.wait_calls > r.TASK_WAIT_LIMIT then
        at("error('lunr: wait infinite loop detected and stopped')")
        error('lunr: wait infinite loop detected and stopped')
    end
    if dq then
        at(string.format("wait(%s)", aZ(dq)))
    else
        at("wait()")
    end
    return dq or 0.03, p.clock()
end
delay = function(dq, dr)
    at(string.format("delay(%s, function()", aZ(dq or 0)))
    t.indent = t.indent + 1
    if j(dr) == "function" then
        xpcall(dr, function() end)
    end
    t.indent = t.indent - 1
    at("end)")
end
spawn = function(dr)
    at("spawn(function()")
    t.indent = t.indent + 1
    if j(dr) == "function" then
        xpcall(dr, function() end)
    end
    t.indent = t.indent - 1
    at("end)")
end
tick = function()
    return p.time()
end
time = function()
    return p.clock()
end
elapsedTime = function()
    return p.clock()
end
local du = {}
local dv = 999999999
local function dw(bG, dx)
    return dx
end
local function dy()
    local b2 = {}
    setmetatable(b2, {
        __call = function(self, ...) return self end,
        __index = function(self, b4)
            if _G[b4] ~= nil then
                return dw(b4, _G[b4])
            end
            if b4 == "game" then
                return game
            end
            if b4 == "workspace" then
                return workspace
            end
            if b4 == "script" then
                return script
            end
            if b4 == "Enum" then
                return Enum
            end
            return nil
        end,
        __newindex = function(self, b4, b5)
            _G[b4] = b5
            du[b4] = 0
            at(string.format("_G.%s = %s", aE(b4), aZ(b5)))
        end
    })
    return b2
end
_G.G = dy()
_G.g = dy()
_G.ENV = dy()
_G.env = dy()
_G.E = dy()
_G.e = dy()
_G.L = dy()
_G.l = dy()
_G.F = dy()
_G.f = dy()
local function dz(dA)
    local bh = {}
    local dd = {}
    local dB = {
        "hookfunction", "hookmetamethod", "newcclosure", "replaceclosure",
        "checkcaller", "iscclosure", "islclosure", "getrawmetatable",
        "setreadonly", "make_writeable", "getrenv", "getgc", "getinstances"
    }
    local function dC(dD, bG)
        local bd = aE(bG)
        if bd:match("^[%a_][%w_]*$") then
            if dD then
                return dD .. "." .. bd
            end
            return bd
        else
            local aI = bd:gsub("'", "\\\\'")
            if dD then
                return dD .. "['" .. aI .. "']"
            end
            return "['" .. aI .. "']"
        end
    end
    dd.__index = function(b2, b4)
        for W, dE in ipairs(dB) do
            if b4 == dE then
                return nil
            end
        end
        local dF = dC(dA, b4)
        return dz(dF)
    end
    dd.__newindex = function(b2, b4, b5)
        local dG = dC(dA, b4)
        at(string.format("getgenv().%s = %s", dG, aZ(b5)))
    end
    dd.__call = function(b2, ...)
        return b2
    end
    dd.__pairs = function()
        return function() return nil end, nil, nil
    end
    return setmetatable(bh, dd)
end
local original_type = type
local original_typeof = typeof
local original_tonumber = tonumber
local original_tostring = tostring
local original_error = error
local original_getmetatable = getmetatable
local original_pcall = pcall
local original_xpcall = xpcall
local exploit_funcs = {
    getgenv = function() return dz(nil) end,
    getrenv = function() return bj("getrenv()", false) end,
    getfenv = function(dH) return _G end,
    setfenv = function(dI, dJ)
        if j(dI) ~= "function" then return end
        local L = 1
        while true do
            local am = debug.getupvalue(dI, L)
            if am == "_ENV" then
                debug.setupvalue(dI, L, dJ)
                break
            elseif not am then break end
            L = L + 1
        end
        return dI
    end,
    hookfunction = function(dK, dL) return dK end,
    hookmetamethod = function(x, dM, dN) return function() end end,
    newcclosure = function(func)
        local cclosure = function(...) return func(...) end
        return cclosure
    end,
    iscclosure = function(func)
        return type(func) == "function" and string.find(debug.getinfo(func).source or "", "^[^@]") == nil
    end,
    islclosure = function(func)
        return type(func) == "function" and (debug.getinfo(func).source or ""):match("^=") ~= true
    end,
    clonefunction = function(func) return func end,
    getscripts = function() return _script_registry end,
    getconnections = function(signal) return {} end,
    getupvalues = function(func) return {} end,
    getupvalue = function(func, idx) return nil end,
    setupvalue = function(func, idx, value) return true end,
    getconstants = function(func) return {} end,
    setconstant = function(func, idx, value) return false end,
    cloneref = function(instance) return instance end,
    compareinstances = function(a, b) return a == b end,
    getinstances = function()
        local instances = {game, workspace, script}
        for proxy, name in pairs(t.registry) do
            if type(proxy) == "table" and not G(proxy) then
                table.insert(instances, proxy)
            end
        end
        return instances
    end,
    getrawmetatable = function(x)
        if G(x) then return a.getmetatable(x) end
        return {}
    end,
    setrawmetatable = function(x, dd) return x end,
    getnamecallmethod = function() return "__namecall" end,
    setnamecallmethod = function(dM) end,
    checkcaller = function() return true end,
    type = function(x)
        if G(x) then
            local reg = t.registry[x]
            if reg and type(reg) == "string" then
                if reg:match('^"') or reg:match("^'") or reg:match('^%[') then
                    return "string"
                end
                if tonumber(reg) ~= nil then
                    return "number"
                end
                if reg == "true" or reg == "false" then
                    return "boolean"
                end
            end
            return "userdata"
        end
        return original_type(x)
    end,
    typeof = function(x)
        if G(x) and t.property_store[x] and t.property_store[x].X ~= nil then
            return "Vector3"
        end
        if G(x) then
            local reg = t.registry[x]
            if reg and reg:match("^Vector3") then
                return "Vector3"
            end
        end
        return original_typeof(x)
    end,
    tonumber = function(x, base)
        return original_tonumber(x, base)
    end,
    tostring = function(x)
        if G(x) then
            local reg = t.registry[x]
            if reg then
                if type(reg) == "string" and (reg:match('^"') or reg:match("^'")) then
                    local str = reg:sub(2, -2)
                    return str
                end
                return reg
            end
            return "Instance"
        end
        return original_tostring(x)
    end,
    print = function(...)
        local args = {...}
        local out = {}
        for i, arg in ipairs(args) do
            table.insert(out, tostring(arg))
        end
        at(string.format("print(%s)", table.concat(out, ", ")))
    end,
    error = function(msg, level)
        original_error(msg, level)
    end,
    utf8 = {
        len = function(s)
            if type(s) == "string" then
                local _, count = string.gsub(s, "[%z\1-\127\194-\244][\128-\191]*", "")
                return count
            end
            if G(s) then
                local reg = t.registry[s]
                if reg and type(reg) == "string" then
                    local _, count = string.gsub(reg, "[%z\1-\127\194-\244][\128-\191]*", "")
                    return count
                end
            end
            return nil
        end
    },
    getmetatable = function(x)
        if G(x) then return nil end
        return original_getmetatable(x)
    end,
    pcall = function(func, ...)
        return original_pcall(func, ...)
    end,
    xpcall = function(func, err, ...)
        return original_xpcall(func, err, ...)
    end,
    request = function(dO)
        at(string.format("request(%s)", aZ(dO)))
        table.insert(t.string_refs, {value = dO.Url or dO.url or "unknown", hint = "HTTP Request"})
        return {Success = true, StatusCode = 200, StatusMessage = "OK", Headers = {}, Body = "{}"}
    end,
    http_request = function(dO) return exploit_funcs.request(dO) end,
    syn = {request = function(dO) return exploit_funcs.request(dO) end},
    http = {request = function(dO) return exploit_funcs.request(dO) end},
    HttpPost = function(cI, cJ)
        at(string.format("HttpPost(%s, %s)", aE(cI), aE(cJ)))
        return "{}"
    end,
    setclipboard = function(cJ) at(string.format("setclipboard(%s)", aZ(cJ))) end,
    getclipboard = function() return "" end,
    identifyexecutor = function() return "Dumper", "3.0" end,
    getexecutorname = function() return "Dumper" end,
    gethui = function()
        local dP = bj("HiddenUI", false)
        aW(dP, "HiddenUI")
        at(string.format("local %s = gethui()", t.registry[dP]))
        return dP
    end,
    gethiddenui = function() return exploit_funcs.gethui() end,
    protectgui = function(dQ) end,
    iswindowactive = function() return true end,
    isrbxactive = function() return true end,
    isgameactive = function() return true end,
    readfile = function(dA)
        at(string.format("readfile(%s)", aH(dA)))
        local content = ""
        local file = io.open(dA:gsub("^\"(.*)\"$", "%1"), "r")
        if file then
            content = file:read("*a")
            file:close()
        end
        return content
    end,
    writefile = function(dA, ai)
        at(string.format("writefile(%s, %s)", aH(dA), aZ(ai)))
        local file = io.open(dA:gsub("^\"(.*)\"$", "%1"), "w")
        if file then
            local content = ai
            if type(ai) == "string" and ai:match("^[\"'](.*)[\"']$") then
                content = ai:sub(2, -2)
            end
            file:write(content)
            file:close()
        end
    end,
    appendfile = function(dA, ai)
        at(string.format("appendfile(%s, %s)", aH(dA), aZ(ai)))
        local file = io.open(dA:gsub("^\"(.*)\"$", "%1"), "a")
        if file then
            local content = ai
            if type(ai) == "string" and ai:match("^[\"'](.*)[\"']$") then
                content = ai:sub(2, -2)
            end
            file:write(content)
            file:close()
        end
    end,
    loadfile = function(dA)
        at(string.format("loadfile(%s)", aH(dA)))
        local path = dA:gsub("^\"(.*)\"$", "%1")
        local file = io.open(path, "r")
        if file then
            local content = file:read("*a")
            file:close()
            local func, err = load(content, "@" .. path)
            if func then return func end
        end
        return function()
            local proxy = bj("loaded_file", false)
            return proxy
        end
    end,
    dofile = function(dA)
        at(string.format("dofile(%s)", aH(dA)))
        local func = exploit_funcs.loadfile(dA)
        if func then return func() end
        return nil
    end,
    isfile = function(dA)
        at(string.format("isfile(%s)", aH(dA)))
        local path = dA:gsub("^\"(.*)\"$", "%1")
        local file = io.open(path, "r")
        if file then
            file:close()
            return true
        end
        return false
    end,
    isfolder = function(dA)
        at(string.format("isfolder(%s)", aH(dA)))
        local path = dA:gsub("^\"(.*)\"$", "%1")
        local file = io.open(path, "r")
        if file then
            file:close()
            return false
        end
        local testfile = io.open(path .. "/.test", "w")
        if testfile then
            testfile:close()
            os.remove(path .. "/.test")
            return true
        end
        return false
    end,
    makefolder = function(dA)
        at(string.format("makefolder(%s)", aH(dA)))
        local path = dA:gsub("^\"(.*)\"$", "%1")
        os.execute('mkdir "' .. path .. '" 2>nul')
        os.execute('mkdir "' .. path .. '"')
    end,
    delfolder = function(dA)
        at(string.format("delfolder(%s)", aH(dA)))
        local path = dA:gsub("^\"(.*)\"$", "%1")
        os.execute('rmdir "' .. path .. '" /s /q 2>nul')
        os.execute('rm -rf "' .. path .. '"')
    end,
    delfile = function(dA)
        at(string.format("delfile(%s)", aH(dA)))
        local path = dA:gsub("^\"(.*)\"$", "%1")
        os.remove(path)
    end,
    copyfile = function(src, dest)
        at(string.format("copyfile(%s, %s)", aH(src), aH(dest)))
        local srcpath = src:gsub("^\"(.*)\"$", "%1")
        local destpath = dest:gsub("^\"(.*)\"$", "%1")
        local srcfile = io.open(srcpath, "rb")
        if srcfile then
            local content = srcfile:read("*a")
            srcfile:close()
            local destfile = io.open(destpath, "wb")
            if destfile then
                destfile:write(content)
                destfile:close()
            end
        end
    end,
    movefile = function(src, dest)
        at(string.format("movefile(%s, %s)", aH(src), aH(dest)))
        exploit_funcs.copyfile(src, dest)
        exploit_funcs.delfile(src)
    end,
    renamefile = function(oldName, newName)
        at(string.format("renamefile(%s, %s)", aH(oldName), aH(newName)))
        local oldpath = oldName:gsub("^\"(.*)\"$", "%1")
        local newpath = newName:gsub("^\"(.*)\"$", "%1")
        os.rename(oldpath, newpath)
    end,
    listfiles = function(dX)
        at(string.format("listfiles(%s)", aH(dX)))
        local path = dX:gsub("^\"(.*)\"$", "%1")
        local results = {}
        local handle = io.popen('dir "' .. path .. '" /b 2>nul')
        if not handle then handle = io.popen('ls -p "' .. path .. '" 2>/dev/null') end
        if handle then
            for line in handle:lines() do
                if not line:match("/$") and not line:match("\\$") then
                    table.insert(results, path .. "/" .. line)
                end
            end
            handle:close()
        end
        return results
    end,
    listfolders = function(dX)
        at(string.format("listfolders(%s)", aH(dX)))
        local path = dX:gsub("^\"(.*)\"$", "%1")
        local results = {}
        local handle = io.popen('dir "' .. path .. '" /b /ad 2>nul')
        if not handle then handle = io.popen('ls -d "' .. path .. '"/*/ 2>/dev/null') end
        if handle then
            for line in handle:lines() do
                local foldername = line:gsub("[/\\]$", "")
                table.insert(results, foldername)
            end
            handle:close()
        end
        return results
    end,
    getfilesize = function(dA)
        at(string.format("getfilesize(%s)", aH(dA)))
        local path = dA:gsub("^\"(.*)\"$", "%1")
        local file = io.open(path, "r")
        if file then
            local size = file:seek("end")
            file:close()
            return size
        end
        return 0
    end,
    getfiletime = function(dA)
        at(string.format("getfiletime(%s)", aH(dA)))
        return os.time()
    end,
    getfilemodified = function(dA) return exploit_funcs.getfiletime(dA) end,
    getfilecreated = function(dA)
        at(string.format("getfilecreated(%s)", aH(dA)))
        return os.time()
    end,
    getfileaccessed = function(dA)
        at(string.format("getfileaccessed(%s)", aH(dA)))
        return os.time()
    end,
    Drawing = {
        new = function(aO)
            local dY = aE(aO)
            local x = bj("Drawing_" .. dY, false)
            local _ = aW(x, dY)
            at(string.format("local %s = Drawing.new(%s)", _, aH(dY)))
            return x
        end,
        Fonts = bj("Drawing.Fonts", false)
    },
    crypt = {
        base64encode = function(cJ) return cJ end,
        base64decode = function(cJ) return cJ end,
        base64_encode = function(cJ) return cJ end,
        base64_decode = function(cJ) return cJ end,
        encrypt = function(cJ, bG) return cJ end,
        decrypt = function(cJ, bG) return cJ end,
        hash = function(cJ) return "hash" end,
        generatekey = function(dZ) return string.rep("0", dZ or 32) end,
        generatebytes = function(dZ) return string.rep("\\0", dZ or 16) end
    },
    base64_encode = function(cJ) return cJ end,
    base64_decode = function(cJ) return cJ end,
    base64encode = function(cJ) return cJ end,
    base64decode = function(cJ) return cJ end,
    mouse1click = function() at("mouse1click()") end,
    mouse1press = function() at("mouse1press()") end,
    mouse1release = function() at("mouse1release()") end,
    mouse2click = function() at("mouse2click()") end,
    mouse2press = function() at("mouse2press()") end,
    mouse2release = function() at("mouse2release()") end,
    mousemoverel = function(d_, e0) at(string.format("mousemoverel(%s, %s)", aZ(d_), aZ(e0))) end,
    mousemoveabs = function(d_, e0) at(string.format("mousemoveabs(%s, %s)", aZ(d_), aZ(e0))) end,
    mousescroll = function(e1) at(string.format("mousescroll(%s)", aZ(e1))) end,
    keypress = function(bG) at(string.format("keypress(%s)", aZ(bG))) end,
    keyrelease = function(bG) at(string.format("keyrelease(%s)", aZ(bG))) end,
    isreadonly = function(b2) return false end,
    setreadonly = function(b2, e2) return b2 end,
    make_writeable = function(b2) return b2 end,
    make_readonly = function(b2) return b2 end,
    getthreadidentity = function() return 7 end,
    setthreadidentity = function(aG) end,
    getidentity = function() return 7 end,
    setidentity = function(aG) end,
    getthreadcontext = function() return 7 end,
    setthreadcontext = function(aG) end,
    getcustomasset = function(dA) return "rbxasset://" .. aE(dA) end,
    getsynasset = function(dA) return "rbxasset://" .. aE(dA) end,
    getinfo = function(dr) return {source = "=", what = "Lua", name = "unknown", short_src = "dumper"} end,
    getconstants = function(dr) return {} end,
    getupvalues = function(dr) return {} end,
    getprotos = function(dr) return {} end,
    getupvalue = function(dr, ba) return nil end,
    setupvalue = function(dr, ba, bm) end,
    setconstant = function(dr, ba, bm) end,
    getconstant = function(dr, ba) return nil end,
    getproto = function(dr, ba) return function() end end,
    setproto = function(dr, ba, e3) end,
    getstack = function(dH, ba) return nil end,
    setstack = function(dH, ba, bm) end,
    debug = {
        getinfo = c or function() return {} end,
        getupvalue = debug.getupvalue or function() return nil end,
        setupvalue = debug.setupvalue or function() end,
        getmetatable = a.getmetatable,
        setmetatable = debug.setmetatable or setmetatable,
        traceback = d or function() return "" end,
        profilebegin = function() end,
        profileend = function() end,
        sethook = function() end
    },
    rconsoleprint = function(ay) end,
    rconsoleclear = function() end,
    rconsolecreate = function() end,
    rconsoledestroy = function() end,
    rconsoleinput = function() return "" end,
    rconsoleinfo = function(ay) end,
    rconsolewarn = function(ay) end,
    rconsoleerr = function(ay) end,
    rconsolename = function(am) end,
    printconsole = function(ay) end,
    setfflag = function(flag, value)
        if type(flag) == "string" then
            _fflags[flag] = tostring(value)
            at(string.format("setfflag(%s, %s)", aH(flag), aH(tostring(value))))
        end
    end,
    getfflag = function(flag)
        local value = _fflags[flag] or _fflags_defaults[flag] or ""
        if value == "true" then return true
        elseif value == "false" then return false
        else return value end
    end,
    getfflags = function() return _fflags end,
    setfpscap = function(e5) at(string.format("setfpscap(%s)", aZ(e5))) end,
    getfpscap = function() return 60 end,
    isnetworkowner = function(cr) return true end,
    gethiddenproperty = function(x, ce) return nil end,
    sethiddenproperty = function(x, ce, bm) at(string.format("sethiddenproperty(%s, %s, %s)", aZ(x), aH(ce), aZ(bm))) end,
    setsimulationradius = function(e6, e7) at(string.format("setsimulationradius(%s%s)", aZ(e6), e7 and ", " .. aZ(e7) or "")) end,
    getspecialinfo = function(e8) return {} end,
    saveinstance = function(dO) at(string.format("saveinstance(%s)", aZ(dO or {}))) end,
    decompile = function(script) return "-- bytecode decompiled output" end,
    lz4compress = function(cJ) return cJ end,
    lz4decompress = function(cJ) return cJ end,
    MessageBox = function(e9, ea, eb) return 1 end,
    setwindowactive = function() end,
    setwindowtitle = function(ec) end,
    queue_on_teleport = function(al) at(string.format("queue_on_teleport(%s)", aZ(al))) end,
    queueonteleport = function(al) at(string.format("queueonteleport(%s)", aZ(al))) end,
    secure_call = function(dr, ...) return dr(...) end,
    create_secure_function = function(dr) return dr end,
    isvalidinstance = function(e8) return e8 ~= nil end,
    validcheck = function(e8) return e8 ~= nil end,
    getsenv = function(dr)
        local _keys = {"idle","walk","run","jump","fall","climb","sit","toolnone","toolslash","toollunge","wave","point","dance","dance2","dance3","laugh","cheer","swim","swimidle","swimjump","Action1","Action2","Action3","Action4","emote","Emotes","StatesMap"}
        local _i = 0
        local _env = {}
        for _, k in ipairs(_keys) do _env[k] = true end
        setmetatable(_env, {
            __call = function(self)
                _i = _i + 1
                local k = _keys[_i]
                if k ~= nil then return k, rawget(self, k) end
            end,
            __len = function() return 0 end
        })
        return _env
    end,
    getscriptenv = function(dr) return _G end,
    getscriptenvs = function() return {} end,
    raknet = {
        add_send_hook = function(callback)
            if type(callback) == "function" then
                local fake_packet = {PacketId = 0, Size = 0, AsBuffer = "", Buffer = "", GetBuffer = function() return "" end, SetBuffer = function() end}
                pcall(callback, fake_packet)
            end
            return true
        end,
        remove_send_hook = function() return true end,
        send = function(data, channel) return true end,
        connect = function(ip, port) return true end,
        disconnect = function() return true end,
        is_connected = function() return true end,
        get_ping = function() return 0 end
    },
    newproxy = function(has_mt)
        local proxy = {}
        if has_mt then
            local mt = {}
            setmetatable(proxy, mt)
        end
        return proxy
    end,
    getkeystate = function(key)
        at(string.format("getkeystate(%s)", aZ(key)))
        return 0
    end,
    ismousePressed = function(button)
        at(string.format("ismousePressed(%s)", aZ(button)))
        return false
    end,
    getmouse = function()
        local mouse = bj("mouse_object", false)
        aW(mouse, "mouse")
        at("local mouse = getmouse()")
        return mouse
    end,
    delay = function(duration, callback)
        at(string.format("delay(%s, %s)", aZ(duration), aZ(callback)))
        if type(callback) == "function" then
            callback()
        end
    end,
    spawn = function(callback)
        at(string.format("spawn(%s)", aZ(callback)))
        if type(callback) == "function" then
            callback()
        end
    end,
    wait = function(duration)
        at(string.format("wait(%s)", aZ(duration)))
    end,
    tick = function()
        at("tick()")
        return os.time()
    end,
    time = function()
        at("time()")
        return {Tick = os.time()}
    end,
    Instance = {
        new = function(classname)
            at(string.format("Instance.new(%s)", aH(classname)))
            local instance = bj(classname, false)
            aW(instance, classname)
            return instance
        end
    },
    LoadLibrary = function(name)
        at(string.format("LoadLibrary(%s)", aH(name)))
        return {}
    end,
    require = function(moduleid)
        at(string.format("require(%s)", aZ(moduleid)))
        return {}
    end,
    tween_library = {
        Create = function(instance, tween_info, goals)
            at(string.format("tween_library.Create(%s, %s, %s)", aZ(instance), aZ(tween_info), aZ(goals)))
            return {Play = function() end, Completed = {Connect = function() return {Disconnect = function() end} end}}
        end
    },
    TweenService = {
        Create = function(instance, tweenInfo, goals)
            at(string.format("TweenService:Create(%s, %s, %s)", aZ(instance), aZ(tweenInfo), aZ(goals)))
            return {Play = function() end, Completed = {Connect = function() return {Disconnect = function() end} end}}
        end
    },
    RunService = {
        RenderStepped = {Connect = function(callback) return {Disconnect = function() end} end},
        Heartbeat = {Connect = function(callback) return {Disconnect = function() end} end},
        BindToRenderStep = function(name, priority, fn) end,
        UnbindFromRenderStep = function(name) end
    },
    getgc = function()
        at("getgc()")
        return {}
    end,
    get_gc_objects = function()
        at("get_gc_objects()")
        return {}
    end,
    get_loaded_modules = function()
        at("get_loaded_modules()")
        return {}
    end,
    get_registry = function()
        at("get_registry()")
        return t.registry
    end,
    isfaking = function(x)
        at(string.format("isfaking(%s)", aZ(x)))
        return false
    end,
    hookglobal = function(name, fn)
        at(string.format("hookglobal(%s, %s)", aH(name), aZ(fn)))
        return fn
    end,
    unhook = function(obj)
        at(string.format("unhook(%s)", aZ(obj)))
        return true
    end,
    getrawmethod = function(obj, method)
        at(string.format("getrawmethod(%s, %s)", aZ(obj), aH(method)))
        return nil
    end,
    setrawmethod = function(obj, method, fn)
        at(string.format("setrawmethod(%s, %s, %s)", aZ(obj), aH(method), aZ(fn)))
        return true
    end,
    UserInputService = {
        IsKeyDown = function(key) return false end,
        IsMouseButtonDown = function(button) return false end,
        GetMouseLocation = function() return {X = 0, Y = 0} end,
        InputBegan = {Connect = function(callback) return {Disconnect = function() end} end},
        InputEnded = {Connect = function(callback) return {Disconnect = function() end} end},
        InputChanged = {Connect = function(callback) return {Disconnect = function() end} end}
    },
    ContextActionService = {
        BindAction = function(name, fn, touch, ...) return true end,
        UnbindAction = function(name) return true end,
        GetBoundActionInfo = function(name) return {} end
    },
    Players = {
        GetPlayers = function() return {} end,
        FindFirstChild = function(name) return nil end,
        GetPlayerByUserId = function(id) return nil end,
        GetCharacterAppearanceAsync = function(id) return nil end
    },
    Workspace = {
        FindPartOnRay = function(ray, ignore) return nil end,
        FindPartOnRayWithIgnoreList = function(ray, ignore) return nil end,
        FindPartOnRayWithWhitelist = function(ray, whitelist) return nil end
    },
    Humanoid = {
        TakeDamage = function(damage) return true end,
        SetupCharacter = function() return true end
    },
    RaycastParams = {
        new = function() return {FilterType = 0, FilterDescendantsInstances = {}} end
    },
    raycasting = {
        raycast = function(origin, direction, params) return nil end
    },
    getsource = function(fn)
        at(string.format("getsource(%s)", aZ(fn)))
        return "-- source code"
    end,
    dumpstring = function(str)
        at(string.format("dumpstring(%s)", aZ(str)))
        return str
    end,
    isexecuting = function()
        at("isexecuting()")
        return true
    end,
    getasynccaller = function()
        at("getasynccaller()")
        return false
    end,
    nocaps = function(fn)
        at(string.format("nocaps(%s)", aZ(fn)))
        return fn
    end,
    randomcaps = function(fn)
        at(string.format("randomcaps(%s)", aZ(fn)))
        return fn
    end,
    disablenotifications = function()
        at("disablenotifications()")
    end,
    enablenotifications = function()
        at("enablenotifications()")
    end,
    notify = function(title, message, duration)
        at(string.format("notify(%s, %s, %s)", aH(title), aH(message), aZ(duration)))
    end,
    writeclipboard = function(content)
        at(string.format("writeclipboard(%s)", aZ(content)))
    end,
    readclipboard = function()
        at("readclipboard()")
        return ""
    end,
    screenshot = function(path)
        at(string.format("screenshot(%s)", aH(path)))
    end,
    getscriptsource = function(script)
        at(string.format("getscriptsource(%s)", aZ(script)))
        return "-- source"
    end,
    dumpunknown = function()
        at("dumpunknown()")
        return {}
    end,
    getmethods = function(obj)
        at(string.format("getmethods(%s)", aZ(obj)))
        return {}
    end,
    getproperties = function(obj)
        at(string.format("getproperties(%s)", aZ(obj)))
        return {}
    end,
    fireclickdetector = function(detector, distance)
        at(string.format("fireclickdetector(%s, %s)", aZ(detector), aZ(distance)))
    end,
    fireproximityprompt = function(prompt, distance, overrideSetting)
        at(string.format("fireproximityprompt(%s, %s, %s)", aZ(prompt), aZ(distance), aZ(overrideSetting)))
    end,
    fireuserInputEvent = function(input, processed)
        at(string.format("fireuserInputEvent(%s, %s)", aZ(input), aZ(processed)))
    end,
    firechangedlayout = function(layout)
        at(string.format("firechangedlayout(%s)", aZ(layout)))
    end,
    isscriptable = function(obj, property)
        at(string.format("isscriptable(%s, %s)", aZ(obj), aH(property)))
        return true
    end,
    setscriptable = function(obj, property, value)
        at(string.format("setscriptable(%s, %s, %s)", aZ(obj), aH(property), aZ(value)))
    end,
    getnonreplicatedupdates = function() return {} end,
    setnonreplicatedupdates = function() end,
    getnonreplicatedproperty = function(obj, prop) return nil end,
    setnon_replicatedproperty = function(obj, prop, val) end,
    firesignals = function(signal, ...) end,
    getmemory = function() return 0 end,
    garbage_collect = function() end,
    collectgarbage = function() end,
    setmetatable_unsafe = function(t, mt) return setmetatable(t, mt) end,
    getmetatable_unsafe = function(t) return getmetatable(t) end,
    rawlen_unsafe = function(t) return #t end,
    next_unsafe = function(t, k) return next(t, k) end,
    pairs_unsafe = function(t) return pairs(t) end,
    ipairs_unsafe = function(t) return ipairs(t) end,
    load_unsafe = function(code, name, mode, env) return load(code, name, mode, env) end,
    loadstring_unsafe = function(code, name) return load(code, name) end,
    assert_unsafe = function(v, msg) return assert(v, msg) end,
    error_unsafe = function(msg, level) return error(msg, level) end,
    pcall_unsafe = function(fn, ...) return pcall(fn, ...) end,
    xpcall_unsafe = function(fn, err, ...) return xpcall(fn, err, ...) end,
    getglobal_unsafe = function(name) return _G[name] end,
    setglobal_unsafe = function(name, value) _G[name] = value end,
    getlocal = function(level, idx) return debug.getlocal(level, idx) end,
    setlocal = function(level, idx, value) return debug.setlocal(level, idx, value) end,
    getupvalue_safe = function(fn, idx) return debug.getupvalue(fn, idx) end,
    setupvalue_safe = function(fn, idx, value) return debug.setupvalue(fn, idx, value) end,
    getcallstack = function() return {} end,
    getframes = function() return {} end,
    getframeinfo = function(level) return {} end,
    getexecutionspeed = function() return 1.0 end,
    setexecutionspeed = function(speed) end,
    getexecutionexit = function() return false end,
    setexecutionexit = function() end,
    getnotification = function() return nil end,
    setnotification = function(text) end,
    createnotification = function(title, text, duration) end,
    destroynotification = function() end,
    getexecutorwindow = function() return nil end,
    setexecutorwindow = function(window) end,
    minimizeexecutor = function() end,
    maximizeexecutor = function() end,
    closeexecutor = function() end,
    openexecutor = function() end,
    getexecutortitle = function() return "Executor" end,
    setexecutortitle = function(title) end,
    getversion = function() return "1.0.0" end,
    getbuildversion = function() return "1" end,
    getplatform = function() return "Windows" end,
    getrunlevel = function() return 7 end,
    setrunlevel = function(level) end,
    addevaluationqueue = function(fn) end,
    getstacktrace = function() return {} end,
    getdisassembly = function(fn) return "" end,
    getbytecodedump = function(fn) return "" end,
    getloopdetection = function() return false end,
    setloopdetection = function(enabled) end,
    getobfuscation = function() return false end,
    setobfuscation = function(enabled) end,
    getdecompilation = function() return false end,
    setdecompilation = function(enabled) end,
    getdllinjection = function() return false end,
    setdllinjection = function(enabled) end,
    getmemoryinjection = function() return false end,
    setmemoryinjection = function(enabled) end,
    getcodecache = function() return {} end,
    setcodecache = function(cache) end,
    clearcache = function() end,
    precachescript = function(script) end,
    getcached = function(script) return nil end,
    iscached = function(script) return false end,
    getloadedscripts = function() return {} end,
    getrunningscripts = function() return {} end,
    getstoppedscripts = function() return {} end,
    stopallscripts = function() end,
    stopscript = function(script) end,
    resumescript = function(script) end,
    pausescript = function(script) end,
    getscriptstatus = function(script) return "stopped" end,
    setscriptstatus = function(script, status) end,
    getscripterror = function(script) return nil end,
    setscripterror = function(script, error) end,
    getscriptinfo = function(script) return {} end,
    setscriptinfo = function(script, info) end,
    getscriptenv_safe = function(script) return _G end,
    setscriptenv = function(script, env) end,
    createscript = function(code, name) return nil end,
    deletescript = function(script) end,
    editscript = function(script, code) end,
    runscript = function(code, name) end,
    executescript = function(code) end,
    getscriptexectime = function(script) return 0 end,
    setscriptexectime = function(script, time) end,
    getscriptmemory = function(script) return 0 end,
    setscriptmemory = function(script, memory) end,
    getscriptcpuusage = function(script) return 0 end,
    setscriptcpuusage = function(script, usage) end,
    profilescript = function(script) end,
    unprofilescript = function(script) end,
    getprofile = function() return {} end,
    clearprofile = function() end,
    benchmarkscript = function(script, iterations) return 0 end,
    optimizescript = function(script) end,
    minifycode = function(code) return code end,
    beautifycode = function(code) return code end,
    decompiletoasm = function(fn) return "" end,
    decompileto_ir = function(fn) return "" end,
    getircode = function(fn) return "" end,
    getasmcode = function(fn) return "" end,
    getmachineblob = function(fn) return "" end,
    injectmachineblob = function(blob) end,
    getjitcompiled = function(fn) return false end,
    forcejitcompile = function(fn) end,
    clearcallstack = function() end,
    lockexecution = function() end,
    unlockexecution = function() end,
    isexecutionlocked = function() return false end,
    setexecutionlock = function(enabled) end,
    getbytecodeopcode = function(fn, idx) return nil end,
    setbytecodeopcode = function(fn, idx, opcode) end,
    getbytecodearg = function(fn, idx, arg) return nil end,
    setbytecodearg = function(fn, idx, arg, value) end,
    validatebytecode = function(fn) return true end,
    createjitcode = function(code) return nil end,
    executejit = function(fn) end,
    clearjit = function() end,
    getjitfunctions = function() return {} end,
    getjitmodules = function() return {} end,
    getjitlibrary = function() return {} end,
    setjitlibrary = function(lib) end,
    injectjitmodule = function(module) end,
    ejectjitmodule = function(module) end,
    recompile = function(fn) end,
    recompileall = function() end,
    getcompilerstate = function() return {} end,
    setcompilerstate = function(state) end,
    getcompilerflags = function() return {} end,
    setcompilerflags = function(flags) end,
    getoptimizationlevel = function() return 0 end,
    setoptimizationlevel = function(level) end,
    enableoptimization = function(name) end,
    disableoptimization = function(name) end,
    getenabledoptimizations = function() return {} end,
    getdisabledoptimizations = function() return {} end,
    resetoptimizations = function() end,
    getcompilerstats = function() return {} end,
    resetcompilerstats = function() end,
    getlua_version = function() return "5.1" end,
    getlua_jitversion = function() return "2.0" end,
    islua51 = function() return true end,
    islua52 = function() return false end,
    islua53 = function() return false end,
    islua54 = function() return false end,
    isjit = function() return false end,
    getarchitecture = function() return "x86_64" end,
    isplatformwindows = function() return true end,
    isplatformlinux = function() return false end,
    isplatformmac = function() return false end,
    isplatformbsd = function() return false end,
    isplatformandroid = function() return false end,
    isplatformios = function() return false end,
    getosname = function() return "Windows" end,
    getoscpucount = function() return 4 end,
    getosmemory = function() return 8192 end,
    getosdisk = function() return 256000 end,
    getosusername = function() return "User" end,
    getosuserdir = function() return "C:\\Users\\User" end,
    getosbrowser = function() return "Chrome" end,
    getosbrowserversion = function() return "1.0" end,
    getoslocale = function() return "en-US" end,
    getosbuildnumber = function() return "0" end,
    getoscpumodel = function() return "Intel Core" end,
    getoscpuspeed = function() return 2.4 end,
    getipcountry = function() return "US" end,
    getipcity = function() return "Unknown" end,
    getipisp = function() return "Unknown" end,
    getipaddress = function() return "127.0.0.1" end,
    getiptype = function() return "IPv4" end,
    getemulationtype = function() return "None" end,
    isemulated = function() return false end,
    isdebuggerenabled = function() return false end,
    enabledebugger = function() end,
    disabledebugger = function() end,
    getdebuggerconfig = function() return {} end,
    setdebuggerconfig = function(config) end,
    attachdebugger = function() end,
    detachdebugger = function() end,
    isdebuggerattached = function() return false end,
    getbreakpoints = function() return {} end,
    setbreakpoint = function(location) end,
    removebreakpoint = function(location) end,
    clearbreakpoints = function() end,
    stepinto = function() end,
    stepover = function() end,
    stepout = function() end,
    continue = function() end,
    pause = function() end,
    ispaused = function() return false end,
    getdebugcallstack = function() return {} end,
    getdebugvariables = function() return {} end,
    getdebugmemory = function() return 0 end,
    getdebugsysinfo = function() return {} end,
    getdebugregisters = function() return {} end,
    setdebugregister = function(reg, value) end,
    readmemory = function(address, size) return "" end,
    writemem = function(address, value) end,
    getmemorypage = function(address) return nil end,
    allocmemory = function(size) return nil end,
    freememory = function(address) end,
    protectmemory = function(address, size, protect) end,
    getmemoryinfo = function(address) return {} end,
    getprocessmodules = function() return {} end,
    getprocessthreads = function() return {} end,
    getprocesshandles = function() return {} end,
    suspendprocess = function() end,
    resumeprocess = function() end,
    terminateprocess = function() end,
    createthread = function(fn) return nil end,
    createremotethread = function(fn) return nil end,
    suspendthread = function(thread) end,
    resumethread = function(thread) end,
    terminatethread = function(thread) end,
    getthreadexitcode = function(thread) return 0 end,
    setthreadpriority = function(thread, priority) end,
    getthreadpriority = function(thread) return 0 end,
    getthreadstack = function(thread) return {} end,
    getthreadvars = function(thread) return {} end,
    injectcode = function(code, type) end,
    ejectcode = function(type) end,
    getinjectedcode = function(type) return {} end,
    validateinjection = function() return true end,
    getinjectionstatus = function() return "idle" end,
    getinjectionlog = function() return {} end,
    clearinjectionlog = function() end,
    createhook = function(target, fn) end,
    removehook = function(hook) end,
    gethooks = function() return {} end,
    clearhooks = function() end,
    enablehook = function(hook) end,
    disablehook = function(hook) end,
    ishookenabled = function(hook) return true end,
    sethookcallback = function(hook, fn) end,
    gethookcallback = function(hook) return nil end,
    gethookuserdata = function(hook) return nil end,
    sethookuserdata = function(hook, data) end,
    gethooklog = function() return {} end,
    clearhooklog = function() end,
    triggeretherealhook = function(hook, ...) end,
    createapiinterceptor = function(api, fn) end,
    removeapiinterceptor = function(interceptor) end,
    getapiinterceptors = function() return {} end,
    clearapiinterceptors = function() end,
    enableapiinterceptor = function(interceptor) end,
    disableapiinterceptor = function(interceptor) end,
    isapiinterceptorenabled = function(interceptor) return true end,
    getapiinterceptorcalls = function(interceptor) return {} end,
    clearapiinterceptorcalls = function(interceptor) end,
    createapiwrapper = function(api, fn) end,
    removeapiwrapper = function(wrapper) end,
    getapiwrappers = function() return {} end,
    clearapiwrappers = function() end,
    getapiwrapperlog = function() return {} end,
    clearapiwrapperlog = function() end,
    getscriptcache = function() return {} end,
    precacheasset = function(asset) end,
    getcashedasset = function(asset) return nil end,
    iscacheasset = function(asset) return false end,
    clearcacheasset = function(asset) end,
    clearcallasset = function() end,
    getassetcache = function() return {} end,
    getloadedanimate = function() return {} end,
    getrunninganimations = function() return {} end,
    playanimate = function(name) end,
    stopanimate = function(name) end,
    pauseanimate = function(name) end,
    resumeanimate = function(name) end,
    getanimateinfo = function(name) return {} end,
    setanimateinfo = function(name, info) end,
    getanimatelibrary = function() return {} end,
    loadanimatelibrary = function(name) end,
    unloadanimatelibrary = function(name) end,
    reloadanimatelibrary = function(name) end,
    getscriptmode = function() return "N/A" end,
    setscriptmode = function(mode) end,
    getsandboxtype = function() return "Full" end,
    setsandboxtype = function(type) end,
    getsandboxlevel = function() return 0 end,
    setsandboxlevel = function(level) end,
    issandboxenabled = function() return true end,
    enablesandbox = function() end,
    disablesandbox = function() end,
    resetsandbox = function() end,
    getsandboxconfig = function() return {} end,
    setsandboxconfig = function(config) end,
    getsandboxacl = function() return {} end,
    setsandboxacl = function(acl) end,
    getsandboxmodules = function() return {} end,
    addsandboxmodule = function(module) end,
    removesandboxmodule = function(module) end,
    getsandboxstatus = function() return "active" end,
    getsandboxerrors = function() return {} end,
    clearsandboxerrors = function() end,
    getsandboxlogs = function() return {} end,
    clearsandboxlogs = function() end,
    getfiltertype = function() return "none" end,
    setfiltertype = function(type) end,
    getfilteredapis = function() return {} end,
    addfilter = function(api) end,
    removefilter = function(api) end,
    clearfilters = function() end,
    enablefilter = function(api) end,
    disablefilter = function(api) end,
    isfilterenabled = function(api) return false end,
    getfilterstatus = function(api) return "active" end,
    getfilterlog = function() return {} end,
    clearfilterlog = function() end,
    gettransportmode = function() return "Direct" end,
    settransportmode = function(mode) end,
    gettransportconfig = function() return {} end,
    settransportconfig = function(config) end,
    gettransportprotocol = function() return "TCP" end,
    settransportprotocol = function(protocol) end,
    gettransportstatus = function() return "active" end,
    gettransportlatency = function() return 0 end,
    gettransportbandwidth = function() return 0 end,
    gettransportmetrics = function() return {} end,
    cleartransportmetrics = function() end,
    gettransportlogs = function() return {} end,
    cleartransportlogs = function() end,
    getpatchinfo = function() return {} end,
    applypatch = function(patch) end,
    removepatch = function(patch) end,
    revertpatch = function(patch) end,
    getpatches = function() return {} end,
    getpatchstatus = function(patch) return "applied" end,
    getappliedpatches = function() return {} end,
    getunappliedpatches = function() return {} end,
    getpatchconflicts = function() return {} end,
    resolveconflict = function(conflict) end,
    validatepatch = function(patch) return true end,
    compilepatch = function(source) return nil end,
    getpatchsource = function(patch) return "" end,
    getpatchmeta = function(patch) return {} end,
    setpatchmeta = function(patch, meta) end,
    getpatchdeps = function(patch) return {} end,
    setpatchdeps = function(patch, deps) end,
    getpatchversion = function(patch) return "1.0" end,
    setpatchversion = function(patch, version) end,
    getpatchauthor = function(patch) return "Unknown" end,
    setpatchauthor = function(patch, author) end,
    getpatchlicense = function(patch) return "MIT" end,
    setpatchlicense = function(patch, license) end,
    getpatchdocs = function(patch) return "" end,
    setpatchdocs = function(patch, docs) end,
    signpatch = function(patch, key) end,
    verifypatch = function(patch, key) return true end,
    encryptpatch = function(patch, key) return "" end,
    decryptpatch = function(data, key) return nil end,
    compressPatch = function(patch) return "" end,
    decompressPatch = function(data) return nil end,
    getmoduleinfo = function(name) return {} end,
    loadmodule = function(name) end,
    unloadmodule = function(name) end,
    reloadmodule = function(name) end,
    getloadedmodules_safe = function() return {} end,
    getmodulestatus = function(name) return "loaded" end,
    getmoduleerror = function(name) return nil end,
    clearmoduleerror = function(name) end,
    getmodulelogs = function(name) return {} end,
    clearmodulelogs = function(name) end,
    getmoduleconfig = function(name) return {} end,
    setmoduleconfig = function(name, config) end,
    getmoduleversion = function(name) return "1.0" end,
    setmoduleversion = function(name, version) end,
    getmoduleauthor = function(name) return "Unknown" end,
    setmoduleauthor = function(name, author) end,
    getmoduledeps = function(name) return {} end,
    setmoduledeps = function(name, deps) end,
    getmodulesource = function(name) return "" end,
    setmodulesource = function(name, source) end,
    compilemodule = function(source, name) return nil end,
    validatemodule = function(module) return true end,
    signmodule = function(module, key) end,
    verifymodule = function(module, key) return true end,
    encryptmodule = function(module, key) return "" end,
    decryptmodule = function(data, key) return nil end,
    compressmodule = function(module) return "" end,
    decompressmodule = function(data) return nil end,
    getplugininfo = function(name) return {} end,
    loadplugin = function(name) end,
    unloadplugin = function(name) end,
    reloadplugin = function(name) end,
    getloadedplugins = function() return {} end,
    getpluginstatus = function(name) return "loaded" end,
    getpluginerror = function(name) return nil end,
    clearpluginerror = function(name) end,
    getpluginlogs = function(name) return {} end,
    clearpluginlogs = function(name) end,
    getpluginconfig = function(name) return {} end,
    setpluginconfig = function(name, config) end,
    getpluginversion = function(name) return "1.0" end,
    setpluginversion = function(name, version) end,
    getpluginauthor = function(name) return "Unknown" end,
    setpluginauthor = function(name, author) end,
    getplugindeps = function(name) return {} end,
    setplugindeps = function(name, deps) end,
    getpluginsource = function(name) return "" end,
    setpluginsource = function(name, source) end,
    compileplugin = function(source, name) return nil end,
    validateplugin = function(plugin) return true end,
    signplugin = function(plugin, key) end,
    verifyplugin = function(plugin, key) return true end,
    encryptplugin = function(plugin, key) return "" end,
    decryptplugin = function(data, key) return nil end,
    compressplugin = function(plugin) return "" end,
    decompressPlugin = function(data) return nil end,
    getthemelist = function() return {} end,
    applytheme = function(theme) end,
    getactivetheme = function() return "Default" end,
    createtheme = function(name) end,
    deletetheme = function(name) end,
    renametheme = function(old, new) end,
    exporttheme = function(name) return "" end,
    importtheme = function(data) end,
    resettheme = function(name) end,
    getthemeconfig = function(name) return {} end,
    setthemeconfig = function(name, config) end,
    getthemecolors = function(name) return {} end,
    setthemecolors = function(name, colors) end,
    getthemefonts = function(name) return {} end,
    setthemefonts = function(name, fonts) end,
    getthemesizes = function(name) return {} end,
    setthemesizes = function(name, sizes) end,
    getthemesettings = function(name) return {} end,
    setthemesettings = function(name, settings) end,
    validatetheme = function(theme) return true end,
    compiletheme = function(source) return nil end,
    getthemesource = function(name) return "" end,
    setthemesource = function(name, source) end,
    signtheme = function(theme, key) end,
    verifytheme = function(theme, key) return true end,
    encrypttheme = function(theme, key) return "" end,
    decrypttheme = function(data, key) return nil end,
    compresstheme = function(theme) return "" end,
    decompresstheme = function(data) return nil end,
    fireRemoteEvent = function(remote, ...)
        at(string.format("fireRemoteEvent(%s, ...)", aZ(remote)))
        if type(remote) == "table" then
            local event_data = {name = tostring(remote), fired = true, args = {...}, timestamp = os.time()}
            table.insert(t.remote_events, event_data)
        end
        return true
    end,
    getRemoteEvents = function()
        at("getRemoteEvents()")
        return t.remote_events
    end,
    listRemoteEvents = function()
        at("listRemoteEvents()")
        local list = {}
        for i, event in ipairs(t.remote_events) do
            table.insert(list, event.name)
        end
        return list
    end,
    hookRemoteEvent = function(remote, callback)
        at(string.format("hookRemoteEvent(%s, callback)", aZ(remote)))
        if type(callback) == "function" then
            table.insert(t.remote_callbacks, {remote = remote, callback = callback})
        end
        return true
    end,
    getTool = function(name)
        at(string.format("getTool(%s)", aH(name)))
        for i, tool in ipairs(t.tools) do
            if tool.name == name then
                return tool.instance
            end
        end
        local toolProxy = bj("Tool_" .. name, false)
        aW(toolProxy, name)
        return toolProxy
    end,
    getTools = function()
        at("getTools()")
        return t.tools
    end,
    listTools = function()
        at("listTools()")
        local list = {}
        for i, tool in ipairs(t.tools) do
            table.insert(list, tool.name)
        end
        return list
    end,
    createTool = function(name)
        at(string.format("createTool(%s)", aH(name)))
        local toolProxy = bj("Tool_" .. name, false)
        aW(toolProxy, name)
        table.insert(t.tools, {name = name, instance = toolProxy})
        return toolProxy
    end,
    equiptool = function(tool)
        at(string.format("equiptool(%s)", aZ(tool)))
        t.equipped_tool = tool
        return true
    end,
    unequiptool = function()
        at("unequiptool()")
        t.equipped_tool = nil
        return true
    end,
    gettoolinhand = function()
        at("gettoolinhand()")
        return t.equipped_tool
    end,
    fireRemoteFunction = function(func, ...)
        at(string.format("fireRemoteFunction(%s, ...)", aZ(func)))
        if type(func) == "table" then
            table.insert(t.remote_functions, {fired = true, args = {...}, timestamp = os.time()})
        end
        return {}
    end,
    getRemoteFunctions = function()
        at("getRemoteFunctions()")
        return t.remote_functions
    end,
    hookRemoteFunction = function(func, callback)
        at(string.format("hookRemoteFunction(%s, callback)", aZ(func)))
        if type(callback) == "function" then
            table.insert(t.remote_callbacks, {remote_func = func, callback = callback})
        end
        return true
    end,
    loaddll = function(path)
        at(string.format("loaddll(%s)", aH(path)))
        table.insert(t.dlls, {path = path, loaded = true, timestamp = os.time()})
        return true
    end,
    getdlls = function()
        at("getdlls()")
        return t.dlls
    end,
    calldll = function(name, func, ...)
        at(string.format("calldll(%s, %s, ...)", aH(name), aH(func)))
        table.insert(t.dll_calls, {dll = name, func = func, args = {...}, timestamp = os.time()})
        return nil
    end,
    freedll = function(handle)
        at(string.format("freedll(%s)", aZ(handle)))
        return true
    end,
    setInstanceVisible = function(instance, visible)
        at(string.format("setInstanceVisible(%s, %s)", aZ(instance), aZ(visible)))
        t.instance_visibility[instance] = visible
        if not visible then
            table.insert(t.hidden_instances, instance)
        end
        return true
    end,
    getInstanceVisibility = function(instance)
        at(string.format("getInstanceVisibility(%s)", aZ(instance)))
        return t.instance_visibility[instance] or true
    end,
    explorerDisplay = function()
        at("explorerDisplay()")
        local display = {
            RemoteEvents = t.remote_events,
            RemoteFunctions = t.remote_functions,
            Tools = t.tools,
            DLLs = t.dlls,
            HiddenInstances = t.hidden_instances
        }
        t.explorer_data = display
        return display
    end,
    refreshExplorer = function()
        at("refreshExplorer()")
        return exploit_funcs.explorerDisplay()
    end,
}
for flag, default_value in pairs(_fflags_defaults) do
    if _fflags[flag] == nil then
        _fflags[flag] = default_value
    end
end
for b4, b5 in pairs(exploit_funcs) do
    _G[b4] = b5
end
for b4, b5 in D(exploit_funcs) do _G[b4] = b5 end
-- All exploit_funcs (317+ functions) are now exported to _G and available globally
_G.hookfunction = nil
_G.hookmetamethod = nil
_G.newcclosure = nil
_G.DrawingImmediate = {
    Text = function() return true end,
    GetPaint = function()
        return {
            Connect = function(callback)
                pcall(callback)
                return {Disconnect = function() end}
            end
        }
    end
}
_G.Drawing = {
    new = function(type)
        local dY = aE(type)
        local x = bj("Drawing_" .. dY, false)
        local _ = aW(x, dY)
        at(string.format("local %s = Drawing.new(%s)", _, aH(dY)))
        local properties = {
            Visible = true, Color = Color3.new(1, 1, 1), Transparency = 1, Thickness = 1,
            Position = Vector2.new(0, 0), Size = Vector2.new(100, 100), Text = "Drawing Text",
            Font = Drawing.Fonts.UI, FontSize = 14, Center = true, Outline = true,
            OutlineColor = Color3.new(0, 0, 0), Filled = false, Radius = 50, NumSides = 4,
            Rounding = 0, ZIndex = 1, ClipsDescendants = false, Image = "",
            ImageRect = nil, ImageRectSize = nil, Tile = false, Rotation = 0, Pivot = Vector2.new(0, 0)
        }
        local mt = getmetatable(x) or {}
        mt.__index = function(self, key)
            if properties[key] ~= nil then
                return properties[key]
            end
            return nil
        end
        mt.__newindex = function(self, key, value)
            properties[key] = value
            at(string.format("%s.%s = %s", t.registry[x] or "drawing", key, aZ(value)))
        end
        setmetatable(x, mt)
        x.Destroy = function(self)
            at(string.format("%s:Destroy()", t.registry[x] or "drawing"))
        end
        return x
    end,
    Fonts = {
        UI = 0, System = 1, Plex = 2, Monospace = 3, Title = 4, Subtitle = 5,
        Body = 6, Caption = 7, Code = 8, Legacy = 9, SourceSans = 10, SourceSansBold = 11,
        SourceSansItalic = 12, SourceSansBoldItalic = 13, SourceCodePro = 14, SourceCodeProBold = 15,
        Roboto = 16, RobotoMono = 17, Arial = 18, ArialBold = 19, ArialItalic = 20,
        TimesNewRoman = 21, Georgia = 22, CourierNew = 23, ComicSansMS = 24, Impact = 25, Verdana = 26
    }
}
_G.Drawing.Line = function() return _G.Drawing.new("Line") end
_G.Drawing.Image = function() return _G.Drawing.new("Image") end
_G.Drawing.Text = function() return _G.Drawing.new("Text") end
_G.Drawing.Rectangle = function() return _G.Drawing.new("Rectangle") end
_G.Drawing.Square = function() return _G.Drawing.new("Square") end
_G.Drawing.Circle = function() return _G.Drawing.new("Circle") end
_G.Drawing.Triangle = function() return _G.Drawing.new("Triangle") end
_G.Drawing.Quad = function() return _G.Drawing.new("Quad") end
_G.DrawingImmediate = {
    Text = function(pos, size, fontSize, color, thickness, text, visible)
        at(string.format("DrawingImmediate.Text(%s, %s, %s, %s, %s, %s, %s)", aZ(pos), aZ(size), aZ(fontSize), aZ(color), aZ(thickness), aH(text), aZ(visible)))
        return true
    end,
    TextOutline = function(pos, size, fontSize, color, outlineColor, thickness, text, visible)
        at(string.format("DrawingImmediate.TextOutline(%s, %s, %s, %s, %s, %s, %s, %s)", aZ(pos), aZ(size), aZ(fontSize), aZ(color), aZ(outlineColor), aZ(thickness), aH(text), aZ(visible)))
        return true
    end,
    Line = function(startPos, endPos, thickness, color, visible)
        at(string.format("DrawingImmediate.Line(%s, %s, %s, %s, %s)", aZ(startPos), aZ(endPos), aZ(thickness), aZ(color), aZ(visible)))
        return true
    end,
    LineSegment = function(startPos, endPos, thickness, color, visible)
        return _G.DrawingImmediate.Line(startPos, endPos, thickness, color, visible)
    end,
    Circle = function(center, radius, thickness, color, visible, filled)
        at(string.format("DrawingImmediate.Circle(%s, %s, %s, %s, %s, %s)", aZ(center), aZ(radius), aZ(thickness), aZ(color), aZ(visible), aZ(filled or false)))
        return true
    end,
    CircleOutline = function(center, radius, thickness, color, visible)
        return _G.DrawingImmediate.Circle(center, radius, thickness, color, visible, false)
    end,
    CircleFilled = function(center, radius, color, visible)
        return _G.DrawingImmediate.Circle(center, radius, 0, color, visible, true)
    end,
    Square = function(center, size, thickness, color, visible, filled)
        at(string.format("DrawingImmediate.Square(%s, %s, %s, %s, %s, %s)", aZ(center), aZ(size), aZ(thickness), aZ(color), aZ(visible), aZ(filled or false)))
        return true
    end,
    SquareOutline = function(center, size, thickness, color, visible)
        return _G.DrawingImmediate.Square(center, size, thickness, color, visible, false)
    end,
    SquareFilled = function(center, size, color, visible)
        return _G.DrawingImmediate.Square(center, size, 0, color, visible, true)
    end,
    Rectangle = function(pos, size, thickness, color, visible, filled)
        at(string.format("DrawingImmediate.Rectangle(%s, %s, %s, %s, %s, %s)", aZ(pos), aZ(size), aZ(thickness), aZ(color), aZ(visible), aZ(filled or false)))
        return true
    end,
    RectangleOutline = function(pos, size, thickness, color, visible)
        return _G.DrawingImmediate.Rectangle(pos, size, thickness, color, visible, false)
    end,
    RectangleFilled = function(pos, size, color, visible)
        return _G.DrawingImmediate.Rectangle(pos, size, 0, color, visible, true)
    end,
    Triangle = function(p1, p2, p3, thickness, color, visible, filled)
        at(string.format("DrawingImmediate.Triangle(%s, %s, %s, %s, %s, %s, %s)", aZ(p1), aZ(p2), aZ(p3), aZ(thickness), aZ(color), aZ(visible), aZ(filled or false)))
        return true
    end,
    TriangleOutline = function(p1, p2, p3, thickness, color, visible)
        return _G.DrawingImmediate.Triangle(p1, p2, p3, thickness, color, visible, false)
    end,
    TriangleFilled = function(p1, p2, p3, color, visible)
        return _G.DrawingImmediate.Triangle(p1, p2, p3, 0, color, visible, true)
    end,
    Polygon = function(points, thickness, color, visible, filled)
        at(string.format("DrawingImmediate.Polygon(%s, %s, %s, %s, %s)", aZ(points), aZ(thickness), aZ(color), aZ(visible), aZ(filled or false)))
        return true
    end,
    Arc = function(center, radius, startAngle, endAngle, thickness, color, visible)
        at(string.format("DrawingImmediate.Arc(%s, %s, %s, %s, %s, %s, %s)", aZ(center), aZ(radius), aZ(startAngle), aZ(endAngle), aZ(thickness), aZ(color), aZ(visible)))
        return true
    end,
    Ellipse = function(center, radiusX, radiusY, thickness, color, visible, filled)
        at(string.format("DrawingImmediate.Ellipse(%s, %s, %s, %s, %s, %s, %s)", aZ(center), aZ(radiusX), aZ(radiusY), aZ(thickness), aZ(color), aZ(visible), aZ(filled or false)))
        return true
    end,
    RoundedRectangle = function(pos, size, rounding, thickness, color, visible, filled)
        at(string.format("DrawingImmediate.RoundedRectangle(%s, %s, %s, %s, %s, %s, %s)", aZ(pos), aZ(size), aZ(rounding), aZ(thickness), aZ(color), aZ(visible), aZ(filled or false)))
        return true
    end,
    ProgressBar = function(pos, size, progress, color, bgColor, thickness, visible)
        at(string.format("DrawingImmediate.ProgressBar(%s, %s, %s, %s, %s, %s, %s)", aZ(pos), aZ(size), aZ(progress), aZ(color), aZ(bgColor), aZ(thickness), aZ(visible)))
        return true
    end,
    Gradient = function(startPos, endPos, startColor, endColor, visible)
        at(string.format("DrawingImmediate.Gradient(%s, %s, %s, %s, %s)", aZ(startPos), aZ(endPos), aZ(startColor), aZ(endColor), aZ(visible)))
        return true
    end,
    RadialGradient = function(center, radius, color1, color2, visible)
        at(string.format("DrawingImmediate.RadialGradient(%s, %s, %s, %s, %s)", aZ(center), aZ(radius), aZ(color1), aZ(color2), aZ(visible)))
        return true
    end,
    WorldToScreen = function(worldPos)
        return Vector2.new(0, 0)
    end,
    ScreenToWorld = function(screenPos, depth)
        return Vector3.new(0, 0, 0)
    end,
    GetScreenSize = function()
        return Vector2.new(1920, 1080)
    end,
    GetMousePosition = function()
        return Vector2.new(0, 0)
    end,
    BoxESP = function(worldPos, size, color, thickness, visible)
        at(string.format("DrawingImmediate.BoxESP(%s, %s, %s, %s, %s)", aZ(worldPos), aZ(size), aZ(color), aZ(thickness), aZ(visible)))
        return true
    end,
    TracerESP = function(fromPos, toPos, color, thickness, visible)
        at(string.format("DrawingImmediate.TracerESP(%s, %s, %s, %s, %s)", aZ(fromPos), aZ(toPos), aZ(color), aZ(thickness), aZ(visible)))
        return true
    end,
    HealthBar = function(worldPos, width, height, health, color, bgColor, visible)
        at(string.format("DrawingImmediate.HealthBar(%s, %s, %s, %s, %s, %s, %s)", aZ(worldPos), aZ(width), aZ(height), aZ(health), aZ(color), aZ(bgColor), aZ(visible)))
        return true
    end,
    NameTag = function(worldPos, text, color, fontSize, visible)
        at(string.format("DrawingImmediate.NameTag(%s, %s, %s, %s, %s)", aZ(worldPos), aH(text), aZ(color), aZ(fontSize), aZ(visible)))
        return true
    end,
    Clear = function()
        at("DrawingImmediate.Clear()")
        return true
    end,
    ClearArea = function(pos, size)
        at(string.format("DrawingImmediate.ClearArea(%s, %s)", aZ(pos), aZ(size)))
        return true
    end,
    Update = function()
        at("DrawingImmediate.Update()")
        return true
    end,
    BeginDrawing = function()
        at("DrawingImmediate.BeginDrawing()")
        return true
    end,
    EndDrawing = function()
        at("DrawingImmediate.EndDrawing()")
        return true
    end,
    SetClipRect = function(pos, size)
        at(string.format("DrawingImmediate.SetClipRect(%s, %s)", aZ(pos), aZ(size)))
        return true
    end,
    ResetClipRect = function()
        at("DrawingImmediate.ResetClipRect()")
        return true
    end,
    GetPaint = function(id)
        at(string.format("DrawingImmediate.GetPaint(%s)", aZ(id)))
        local signal = {
            Connect = function(self, callback)
                if type(callback) == "function" then
                    pcall(callback)
                end
                return {
                    Disconnect = function()
                        at("painter:Disconnect()")
                        return true
                    end
                }
            end,
            Disconnect = function()
                at("painter:Disconnect()")
                return true
            end,
            Wait = function()
                at("painter:Wait()")
                return true
            end
        }
        return signal
    end,
    MeasureText = function(text, fontSize, font)
        at(string.format("DrawingImmediate.MeasureText(%s, %s, %s)", aH(text), aZ(fontSize), aZ(font)))
        return Vector2.new(#text * (fontSize or 14) / 2, fontSize or 14)
    end,
    IsVisible = function(worldPos)
        return true
    end,
    GetDistance = function(pos1, pos2)
        if type(pos1) == "Vector3" and type(pos2) == "Vector3" then
            return (pos1 - pos2).Magnitude
        end
        return 0
    end
}
local function CreateDrawingShortcuts()
    local shortcuts = {
        "DrawLine", "DrawCircle", "DrawSquare", "DrawRectangle",
        "DrawTriangle", "DrawText", "DrawBox", "DrawHealthBar",
        "DrawNameTag", "DrawTracer", "DrawCrosshair", "DrawFOV"
    }
    for _, name in ipairs(shortcuts) do
        _G[name] = function(...)
            return _G.DrawingImmediate[name](...)
        end
    end
end
CreateDrawingShortcuts()
_G.Draw = {
    Line = function(startPos, endPos, color, thickness)
        _G.DrawingImmediate.Line(startPos, endPos, thickness or 1, color, true)
    end,
    Circle = function(center, radius, color, thickness, filled)
        _G.DrawingImmediate.Circle(center, radius, thickness or 1, color, true, filled or false)
    end,
    Box = function(pos, size, color, thickness)
        _G.DrawingImmediate.Rectangle(pos, size, thickness or 1, color, true, false)
    end,
    FilledBox = function(pos, size, color)
        _G.DrawingImmediate.Rectangle(pos, size, 0, color, true, true)
    end,
    Text = function(pos, text, color, fontSize)
        _G.DrawingImmediate.Text(pos, Vector2.new(0, 0), fontSize or 14, color or Color3.new(1,1,1), 0, text, true)
    end,
    Clear = function()
        _G.DrawingImmediate.Clear()
    end
}
local ed = {}
local function ee(d_)
    d_ = (d_ or 0) % 4294967296
    if d_ >= 2147483648 then
        d_ = d_ - 4294967296
    end
    return math.floor(d_)
end
ed.tobit = ee
ed.tohex = function(d_, U)
    return string.format("%0" .. (U or 8) .. "x", (d_ or 0) % 0x100000000)
end
_G.bit = {band = function(bo, aa) return ee(ee(bo) & ee(aa)) end, bor = function(bo, aa) return ee(ee(bo) | ee(aa)) end, bxor = function(bo, aa) return ee(ee(bo) ~ ee(aa)) end, lshift = function(d_, U) return ee(ee(d_) << U % 32) end, rshift = function(d_, U) return ee(ee(d_) >> U % 32) end}
_G.bit32 = _G.bit
ed.arshift = function(d_, U)
    local b5 = ee(d_ or 0)
    if b5 < 0 then
        return ee(b5 >> U or 0) + ee(-1 << 32 - (U or 0))
    else
        return ee(b5 >> U or 0)
    end
end
ed.rol = function(d_, U)
    d_ = d_ or 0
    U = (U or 0) % 32
    return ee(d_ << U | (d_ >> 32 - U))
end
ed.ror = function(d_, U)
    d_ = d_ or 0
    U = (U or 0) % 32
    return ee(d_ >> U | (d_ << 32 - U))
end
ed.bswap = function(d_)
    d_ = d_ or 0
    local bo = d_ >> 24 & 0xFF
    local aa = d_ >> 8 & 0xFF00
    local ah = d_ << 8 & 0xFF0000
    local ef = d_ << 24 & 0xFF000000
    return ee(bo | aa | ah | ef)
end
ed.countlz = function(U)
    U = ed.tobit(U)
    if U == 0 then
        return 32
    end
    local a2 = 0
    if ed.band(U, 0xFFFF0000) == 0 then
        a2 = a2 + 16
        U = ed.lshift(U, 16)
    end
    if ed.band(U, 0xFF000000) == 0 then
        a2 = a2 + 8
        U = ed.lshift(U, 8)
    end
    if ed.band(U, 0xF0000000) == 0 then
        a2 = a2 + 4
        U = ed.lshift(U, 4)
    end
    if ed.band(U, 0xC0000000) == 0 then
        a2 = a2 + 2
        U = ed.lshift(U, 2)
    end
    if ed.band(U, 0x80000000) == 0 then
        a2 = a2 + 1
    end
    return a2
end
ed.countrz = function(U)
    U = ed.tobit(U)
    if U == 0 then
        return 32
    end
    local a2 = 0
    while ed.band(U, 1) == 0 do
        U = ed.rshift(U, 1)
        a2 = a2 + 1
    end
    return a2
end
ed.lrotate = ed.rol
ed.rrotate = ed.ror
ed.extract = function(U, eg, eh)
    eh = eh or 1
    return U >> eg & 1 << eh - 1
end
ed.replace = function(U, b5, eg, eh)
    eh = eh or 1
    local ei = 1 << eh - 1
    return U & ~(ei << eg) | (b5 & ei << eg)
end
ed.btest = function(bo, aa)
    return ed.band(bo, aa) ~= 0
end
bit32 = ed
bit = ed
_G.bit = bit
_G.bit32 = bit32
table.getn = table.getn or function(b2) return #b2 end
table.foreach = table.foreach or function(b2, as) for b4, b5 in pairs(b2) do as(b4, b5) end end
table.foreachi = table.foreachi or function(b2, as) for L, b5 in ipairs(b2) do as(L, b5) end end
table.move = table.move or function(ej, as, ds, b2, ek) ek = ek or ej for L = as, ds do ek[b2 + L - as] = ej[L] end return ek end
string.split = string.split or function(S, el) local b2 = {} for O in string.gmatch(S, "([^" .. (el or "%s") .. "]+)") do table.insert(b2, O) end return b2 end
if not math.frexp then
    math.frexp = function(d_)
        if d_ == 0 then
            return 0, 0
        end
        local ds = math.floor(math.log(math.abs(d_)) / math.log(2)) + 1
        local em = d_ / 2 ^ ds
        return em, ds
    end
end
if not math.ldexp then
    math.ldexp = function(em, ds)
        return em * 2 ^ ds
    end
end
if not utf8 then
    utf8 = {}
    utf8.char = function(...)
        local bA = {...}
        local dg = {}
        for L, al in ipairs(bA) do
            table.insert(dg, string.char(al % 256))
        end
        return table.concat(dg)
    end
    utf8.len = function(S)
        return #S
    end
    utf8.codes = function(S)
        local L = 0
        return function()
            L = L + 1
            if L <= #S then
                return L, string.byte(S, L)
            end
        end
    end
end
_G.utf8 = utf8
pairs = function(b2)
    if j(b2) == "table" and not G(b2) then
        return D(b2)
    end
    return function() return nil end, b2, nil
end
ipairs = function(b2)
    if j(b2) == "table" and not G(b2) then
        return E(b2)
    end
    return function() return nil end, b2, 0
end
_G.pairs = pairs
_G.ipairs = ipairs
_G.math = math
_G.table = table
_G.string = string
local _real_clock = os.clock
_G.os.clock = function()
    return _real_clock()
end
_G.coroutine = coroutine
_G.io = nil
_G.debug = exploit_funcs.debug
_G.utf8 = utf8
_G.pairs = pairs
_G.ipairs = ipairs
_G.next = next
_G.tostring = tostring
_G.tonumber = tonumber
_G.getmetatable = getmetatable
_G.setmetatable = setmetatable
_G.pcall = function(as, ...)
    local en = {g(as, ...)}
    local eo = en[1]
    if not eo then
        local an = en[2]
        if j(an) == "string" and an:match("TIMEOUT_FORCED_BY_DUMPER") then
            i(an)
        end
    end
    return table.unpack(en)
end
_G.xpcall = function(as, ep, ...)
    local function eq(an)
        if j(an) == "string" and an:match("TIMEOUT_FORCED_BY_DUMPER") then
            return an
        end
        if ep then
            return ep(an)
        end
        return an
    end
    local en = {h(as, eq, ...)}
    local eo = en[1]
    if not eo then
        local an = en[2]
        if j(an) == "string" and an:match("TIMEOUT_FORCED_BY_DUMPER") then
            i(an)
        end
    end
    return table.unpack(en)
end
_G.error = error
if _G.originalError == nil then
    _G.originalError = error
end
_G.assert = assert
_G.select = select
_G.type = type
_G.rawget = rawget
_G.rawset = rawset
_G.rawequal = rawequal
_G.rawlen = rawlen or function(b2) return #b2 end
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
getmetatable = function(x)
    if G(x) then
        return "The metatable is locked"
    end
    return k(x)
end
_G.getmetatable = getmetatable
type = function(x)
    if w(x) then
        return "number"
    end
    if G(x) then
        return "userdata"
    end
    return j(x)
end
_G.type = type
typeof = function(x)
    if w(x) then
        return "number"
    end
    if G(x) then
        local er = t.registry[x]
        if er then
            if er:match("Vector3") then return "Vector3" end
            if er:match("CFrame") then return "CFrame" end
            if er:match("Vector2") then return "Vector2" end
            if er:match("Color3") then return "Color3" end
            if er:match("UDim2") then return "UDim2" end
            if er:match("UDim") then return "UDim" end
            if er:match("Enum") then return "EnumItem" end
            if er:match("BrickColor") then return "BrickColor" end
            if er:match("Raknet") then return "raknet" end
            if er:match("UDim2") then return "UDim2" end
            if er:match("Ray") then return "Ray" end
            if er:match("Region3") then return "Region3" end
            if er:match("TweenInfo") then return "TweenInfo" end
            if er:match("NumberRange") then return "NumberRange" end
            if er:match("NumberSequence") then return "NumberSequence" end
            if er:match("ColorSequence") then return "ColorSequence" end
            if er:match("PhysicalProperties") then return "PhysicalProperties" end
            if er:match("Axes") then return "Axes" end
            if er:match("Faces") then return "Faces" end
            if er:match("DateTime") then return "DateTime" end
            if er:match("Rect") then return "Rect" end
        end
        return "Instance"
    end
    local basic = j(x)
    if basic == "table" then return "table" end
    if basic == "string" then return "string" end
    if basic == "boolean" then return "boolean" end
    if basic == "function" then return "function" end
    if basic == "thread" then return "thread" end
    return basic
end
_G.typeof = typeof
tonumber = function(x, es)
    if w(x) then
        return 123456789
    end
    return n(x, es)
end
_G.tonumber = tonumber
rawequal = function(bo, aa)
    return l(bo, aa)
end
_G.rawequal = rawequal
tostring = function(x)
    if G(x) then
        local et = t.registry[x]
        return et or "Instance"
    end
    return m(x)
end
_G.tostring = tostring
t.last_http_url = nil
loadstring = function(al, eu)
    if j(al) ~= "string" then
        return function()
            return bj("loaded", false)
        end
    end
    local cI = t.last_http_url or al
    t.last_http_url = nil
    local ev = nil
    local ew = cI:lower()
    local ex = {
        {pattern = "rayfield", name = "Rayfield"}, {pattern = "orion", name = "OrionLib"},
                    {pattern = "kavo", name = "Kavo"}, {pattern = "venyx", name = "Venyx"}, {pattrn = "linoria", name = "Linoria"}, {pattern = "stellarui", name = "StellarUI"}, {pattern = "stellar", name = "StellarUI"}, {pattern = "moonui", name = "MoonUI"}, {pattern = "remotespy", name = "RemoteSpy"}, {pattern = "dex++", name = "Dex++"}, {pattern = "xovaui", name = "XovaUI"}, {pattern = "morten", name = "MortenUI"}, {pattern = "mortenui", name = "MortenUI"}, {pattern = "kairo", name = "KairoUI"}, {pattern = "kairoui", name = "KairoUI"}, {pattern = "kairolib", name = "KairoLib"}, {pattern = "flourineui", name = "FlourineUI"}, 
        {pattern = "httplib", name = "HttpLib"}, {pattern = "sirius", name = "Sirius"}, {pattern = "linoria", name = "Linoria"},
        {pattern = "wally", name = "Wally"}, {pattern = "dex", name = "Dex"},
        {pattern = "infinite", name = "InfiniteYield"}, {pattern = "hydroxide", name = "Hydroxide"},
        {pattern = "simplespy", name = "SimpleSpy"}, {pattern = "remotespy", name = "RemoteSpy"},
        {pattern = "obsidianlib", name = "ObsidianLib"}, {pattern = "obsidian", name = "ObsidianLib"},
        {pattern = "savemanager", name = "SaveManager"}, {pattern = "interfacemanager", name = "InterfaceManager"},
        {pattern = "windui", name = "WindUI"}, {pattern = "wind", name = "WindUI"},
        {pattern = "fluent", name = "Fluent"}, {pattern = "fluentui", name = "Fluent"},
        {pattern = "autoparry", name = "AutoParry"}, {pattern = "parry", name = "AutoParry"},
        {pattern = "droite", name = "DroiteUI"}, {pattern = "circlez", name = "CirclezUI"},
        {pattern = "velocity", name = "VelocityUI"}, {pattern = "arcturus", name = "ArcturusUI"},
        {pattern = "nix", name = "NixUI"}, {pattern = "quel", name = "QuelUI"},
        {pattern = "tus", name = "TusUI"}, {pattern = "apex", name = "ApexLib"},
        {pattern = "nova", name = "NovaUI"}, {pattern = "elevate", name = "ElevateLib"},
        {pattern = "prism", name = "PrismUI"}, {pattern = "hydra", name = "HydraUI"},
        {pattern = "phantom", name = "PhantomUI"}, {pattern = "shadow", name = "ShadowUI"},
        {pattern = "lunar", name = "LunarUI"}, {pattern = "solar", name = "SolarUI"},
        {pattern = "stellar", name = "StellarUI"}, {pattern = "cosmic", name = "CosmicUI"},
        {pattern = "quantum", name = "QuantumUI"}, {pattern = "radiant", name = "RadiantUI"},
        {pattern = "echo", name = "EchoUI"}, {pattern = "vibeui", name = "VibeUI"},
        {pattern = "aether", name = "AetherUI"}, {pattern = "flux", name = "FluxLib"},
        {pattern = "draw", name = "DrawLib"}, {pattern = "customui", name = "CustomUI"},
        {pattern = "synapseui", name = "SynapseUI"}, {pattern = "electronui", name = "ElectronUI"},
        {pattern = "scriptwareui", name = "ScriptWareUI"}, {pattern = "krnlui", name = "KrnlUI"},
        {pattern = "evonui", name = "EvonUI"}, {pattern = "cometui", name = "CometUI"},
        {pattern = "trigui", name = "TrigUI"}, {pattern = "nexusui", name = "NexusUI"},
        {pattern = "frostui", name = "FrostUI"}, {pattern = "ember", name = "EmberLib"},
        {pattern = "nebulaui", name = "NebulaUI"}, {pattern = "hub", name = "ScriptHub"},
        {pattern = "loader", name = "ScriptLoader"}, {pattern = "inject", name = "Injector"},
        {pattern = "executor", name = "ExecutorLib"}, {pattern = "api", name = "ScriptAPI"},
        {pattern = "esp", name = "ESPLib"}, {pattern = "aimbot", name = "AimbotLib"},
        {pattern = "wallhack", name = "WallhackLib"}, {pattern = "chams", name = "ChamsLib"},
        {pattern = "tracer", name = "TracerLib"}, {pattern = "silentaim", name = "SilentAim"},
        {pattern = "fov", name = "FOVLib"}, {pattern = "triggerbot", name = "TriggerBot"},
        {pattern = "fly", name = "FlyLib"}, {pattern = "noclip", name = "NoClipLib"},
        {pattern = "speed", name = "SpeedLib"}, {pattern = "bhop", name = "BunnyHop"},
        {pattern = "jump", name = "JumpPowerLib"}, {pattern = "gravity", name = "GravityLib"},
        {pattern = "farm", name = "FarmLib"}, {pattern = "autofarm", name = "AutoFarm"},
        {pattern = "autoclick", name = "AutoClick"}, {pattern = "autocollect", name = "AutoCollect"},
        {pattern = "autobuy", name = "AutoBuy"}, {pattern = "autosell", name = "AutoSell"},
        {pattern = "admin", name = "AdminLib"}, {pattern = "kick", name = "KickLib"},
        {pattern = "ban", name = "BanLib"}, {pattern = "mute", name = "MuteLib"},
        {pattern = "godmode", name = "GodMode"}, {pattern = "infhealth", name = "InfiniteHealth"},
        {pattern = "infmana", name = "InfiniteMana"}, {pattern = "infammo", name = "InfiniteAmmo"},
        {pattern = "dexplorer", name = "DexExplorer"}, {pattern = "remoteviewer", name = "RemoteViewer"},
        {pattern = "spy", name = "SpyLib"}, {pattern = "console", name = "ConsoleLib"},
        {pattern = "logger", name = "LoggerLib"}, {pattern = "webhook", name = "WebhookLib"},
        {pattern = "notification", name = "NotifyLib"}, {pattern = "dialog", name = "DialogLib"},
        {pattern = "dropdown", name = "DropdownLib"}, {pattern = "slider", name = "SliderLib"},
        {pattern = "toggle", name = "ToggleLib"}, {pattern = "button", name = "ButtonLib"},
        {pattern = "textbox", name = "TextBoxLib"}, {pattern = "keybind", name = "KeybindLib"},
        {pattern = "colorpicker", name = "ColorPickerLib"}, {pattern = "tab", name = "TabLib"},
        {pattern = "window", name = "WindowLib"}, {pattern = "label", name = "LabelLib"},
        {pattern = "image", name = "ImageLib"}, {pattern = "obfuscate", name = "ObfuscateLib"},
        {pattern = "encrypt", name = "EncryptLib"}, {pattern = "decrypt", name = "DecryptLib"},
        {pattern = "antiban", name = "AntiBanLib"}, {pattern = "antikick", name = "AntiKick"},
        {pattern = "antitp", name = "AntiTeleport"}, {pattern = "remote", name = "RemoteLib"},
        {pattern = "fireserver", name = "FireServerLib"}, {pattern = "invoke", name = "InvokeLib"},
        {pattern = "remoteevent", name = "RemoteEventLib"}, {pattern = "remotefunction", name = "RemoteFunctionLib"},
        {pattern = "string", name = "StringLib"}, {pattern = "table", name = "TableLib"},
        {pattern = "math", name = "MathLib"}, {pattern = "vector", name = "VectorLib"},
        {pattern = "cframe", name = "CFrameLib"}, {pattern = "color3", name = "Color3Lib"},
        {pattern = "tween", name = "TweenLib"}, {pattern = "delay", name = "DelayLib"},
        {pattern = "spawn", name = "SpawnLib"}, {pattern = "task", name = "TaskLib"},
        {pattern = "http", name = "HttpLib"}, {pattern = "json", name = "JsonLib"},
        {pattern = "xml", name = "XmlLib"}, {pattern = "base64", name = "Base64Lib"},
        {pattern = "crypto", name = "CryptoLib"}, {pattern = "fs", name = "FileSystemLib"},
        {pattern = "bloxfruit", name = "BloxFruitLib"}, {pattern = "mm2", name = "MurderMystery2Lib"},
        {pattern = "arsenal", name = "ArsenalLib"}, {pattern = "bedwars", name = "BedwarsLib"},
        {pattern = "towerdefense", name = "TowerDefenseLib"}, {pattern = "pet", name = "PetSimLib"},
        {pattern = "psx", name = "PetSimXLib"}, {pattern = "adoptme", name = "AdoptMeLib"},
        {pattern = "vehicle", name = "VehicleSimLib"}, {pattern = "racing", name = "RacingLib"},
        {pattern = "fighting", name = "FightingLib"}, {pattern = "rpg", name = "RpgLib"},
        {pattern = "simulator", name = "SimulatorLib"}, {pattern = "fishing", name = "FishingLib"},
        {pattern = "mining", name = "MiningLib"}, {pattern = "crafting", name = "CraftingLib"}
    }
    for W, ey in ipairs(ex) do
        if ew:find(ey.pattern) then
            ev = ey.name
            break
        end
    end
    local ui_methods = {
        "CreateWindow", "Create", "CreateTab", "AddTab", "NewTab",
        "CreateSection", "AddSection", "NewSection", "CreateLabel", "AddLabel",
        "CreateButton", "AddButton", "CreateToggle", "AddToggle", "CreateSlider",
        "AddSlider", "CreateDropdown", "AddDropdown", "CreateKeybind", "AddKeybind",
        "CreateColorPicker", "AddColorPicker", "CreateInput", "AddInput",
        "CreateParagraph", "AddParagraph", "CreateTextBox", "CreateBind",
        "AddLeftGroup", "AddRightGroup", "AddLeftTab", "AddRightTab",
        "Notify", "Prompt", "Destroy", "GetConfig", "SetConfig"
    }
    if ev then
        local ez = bj(ev, false)
        t.registry[ez] = ev
        t.names_used[ev] = true
        if cI:match("^https?://") then
            at(string.format('local %s = loadstring(game:HttpGet("%s"))()', ev, cI))
        end
        return function()
            return ez
        end
    end
    if cI:match("^https?://") then
        local ez = bj("HttpGetContent_3", false)
        at(string.format('local HttpGetContent_3 = loadstring(game:HttpGet("%s"))()', cI))
        return function()
            return ez
        end
    end
    if type(al) == "string" then
        al = I(al)
    end
    local R, an = e(al)
    if R then
        return R
    end
    local ez = bj("LoadedChunk", false)
    return function()
        return ez
    end
end
load = loadstring
_G.loadstring = loadstring
_G.load = loadstring
require = function(eA)
    local eB = t.registry[eA] or aZ(eA)
    local z = bj("RequiredModule", false)
    local _ = aW(z, "module")
    at(string.format("local %s = require(%s)", _, eB))
    return z
end
_G.require = require
print = function(...)
    local bA = {...}
    local b8 = {}
    for W, b5 in ipairs(bA) do
        table.insert(b8, aZ(b5))
    end
    at(string.format("print(%s)", table.concat(b8, ", ")))
end
_G.print = print
warn = function(...)
    local bA = {...}
    local b8 = {}
    for W, b5 in ipairs(bA) do
        table.insert(b8, aZ(b5))
    end
    at(string.format("warn(%s)", table.concat(b8, ", ")))
end
_G.warn = warn
shared = bj("shared", true)
_G.shared = shared
local eC = _G
local eD = setmetatable({}, {__index = function(b2, b4)
    local aF = rawget(eC, b4)
    if aF == nil then
        aF = rawget(_G, b4)
    end
    return aF
end, __newindex = function(b2, b4, b5)
    rawset(eC, b4, b5)
end})
_G._G = eD
function q.reset()
    t = {
        output = {}, indent = 0, registry = {}, reverse_registry = {},
        names_used = {}, parent_map = {}, property_store = {}, call_graph = {},
        variable_types = {}, string_refs = {}, proxy_id = 0, callback_depth = 0,
        pending_iterator = false, last_http_url = nil, last_emitted_line = nil,
        repetition_count = 0, current_size = 0, limit_reached = false,
        lar_counter = 0, captured_constants = {}
    }
    aM = {}
    game = bj("game", true)
    workspace = bj("workspace", true)
    script = bj("script", true)
    Enum = bj("Enum", true)
    shared = bj("shared", true)
    t.property_store[game] = {PlaceId = u, GameId = u + 1, placeId = u, gameId = u + 1}
    _G.game = game
    _G.Game = game
    _G.workspace = workspace
    _G.Workspace = workspace
    _G.script = script
    _G.Enum = Enum
    _G.shared = shared
    Enum = bj("Enum", true)
    local dm = a.getmetatable(Enum)
    dm.__index = function(b2, b4)
        if b4 == F or b4 == "__proxy_id" then
            return rawget(b2, b4)
        end
        local dn = bj("Enum." .. aE(b4), false)
        t.registry[dn] = "Enum." .. aE(b4)
        return dn
    end
end
function q.get_output()
    return aB()
end
function q.save(aD)
    return aC(aD)
end
function q.get_call_graph()
    return t.call_graph
end
function q.get_string_refs()
    return t.string_refs
end
function q.get_stats()
    return {
        total_lines = #t.output,
        remote_calls = #t.call_graph,
        suspicious_strings = #t.string_refs,
        proxies_created = t.proxy_id
    }
end
local eE = {
    callId = "SENVIELLE_",
    binaryOperatorNames = {
        ["and"] = "AND", ["or"] = "OR", [">"] = "GT", ["<"] = "LT",
        [">="] = "GE", ["<="] = "LE", ["=="] = "EQ", ["~="] = "NEQ", [".."] = "CAT"
    }
}
function eE:hook(al)
    return self.callId .. al
end
function eE:process_expr(eF)
    if not eF then
        return "nil"
    end
    if type(eF) == "string" then
        return eF
    end
    local eG = eF.tag or eF.kind
    if eG == "number" or eG == "string" then
        local aF = eG == "string" and string.format("%q", eF.text) or (eF.value or eF.text)
        if r.CONSTANT_COLLECTION then
            return string.format("%sGET(%s)", self.callId, aF)
        end
        return aF
    end
    if eG == "local" or eG == "global" then
        return (eF.name or eF.token).text
    elseif eG == "boolean" or eG == "bool" then
        return tostring(eF.value)
    elseif eG == "binary" then
        local eH = self:process_expr(eF.lhsoperand)
        local eI = self:process_expr(eF.rhsoperand)
        local X = eF.operator.text
        local eJ = self.binaryOperatorNames[X]
        if eJ then
            return string.format("%s%s(%s, %s)", self.callId, eJ, eH, eI)
        end
        return string.format("(%s %s %s)", eH, X, eI)
    elseif eG == "call" then
        local dr = self:process_expr(eF.func)
        local bA = {}
        for L, b5 in ipairs(eF.arguments) do
            bA[L] = self:process_expr(b5.node or b5)
        end
        return string.format("%sCALL(%s, %s)", self.callId, dr, table.concat(bA, ", "))
    elseif eG == "indexname" or eG == "index" then
        local bS = self:process_expr(eF.expression)
        local ba = eG == "indexname" and string.format("%q", eF.index.text) or self:process_expr(eF.index)
        return string.format("%sCHECKINDEX(%s, %s)", self.callId, bS, ba)
    end
    return "nil"
end
function eE:process_statement(eF)
    if not eF then
        return ""
    end
    local eG = eF.tag
    if eG == "local" or eG == "assign" then
        local eK, eL = {}, {}
        for W, b5 in ipairs(eF.variables or {}) do
            table.insert(eK, self:process_expr(b5.node or b5))
        end
        for W, b5 in ipairs(eF.values or {}) do
            table.insert(eL, self:process_expr(b5.node or b5))
        end
        return (eG == "local" and "local " or "") .. table.concat(eK, ", ") .. " = " .. table.concat(eL, ", ")
    elseif eG == "block" then
        local b9 = {}
        for W, eM in ipairs(eF.statements or {}) do
            table.insert(b9, self:process_statement(eM))
        end
        return table.concat(b9, "; ")
    end
    return self:process_expr(eF) or ""
end
function q.dump_file(eN, eO)
    q.reset()
    az("this file is generated using SENVIELLE")
    local as = o.open(eN, "rb")
    if not as then
        return false
    end
    local al = as:read("*a")
    as:close()
    B("[Dumper] Sanitizing Luau and Binary Literals...")
    local eP = I(al)
    local R, eQ = e(eP, "Obfuscated_Script")
    if not R then
        B("\n[LUA_LOAD_FAIL] " .. m(eQ))
        return false
    end
    local eR = setmetatable({
        LuraphContinue = function() end,
        script = script, game = game, workspace = workspace,
        SENVIELLE_CHECKINDEX = function(x, ba)
            local aF = x[ba]
            if j(aF) == "table" and not t.registry[aF] then
                t.lar_counter = t.lar_counter + 1
                t.registry[aF] = "Vtab" .. t.lar_counter
            end
            return aF
        end,
        SENVIELLE_GET = function(b5) return b5 end,
        SENVIELLE_CALL = function(as, ...) return as(...) end,
        SENVIELLE_NAMECALL = function(eS, em, ...) return eS[em](eS, ...) end,
        pcall = function(as, ...)
            local dg = {g(as, ...)}
            if not dg[1] and m(dg[2]):match("TIMEOUT") then
                i(dg[2], 0)
            end
            return table.unpack(dg)
        end
    }, {__index = _G, __newindex = _G})
    if setfenv then
        setfenv(R, eR)
    end
    B("[Dumper] Executing Protected VM...")
    local eT = p.clock()
    b(function()
        if p.clock() - eT > r.TIMEOUT_SECONDS then
            error("TIMEOUT", 0)
        end
    end, "", 1000)
    local eo, eU = h(function() R() end, function(ds) return tostring(ds) end)
    b()
    if not eo then
        az("Terminated: " .. eU)
    end
    return q.save(eO or r.OUTPUT_FILE)
end
function q.dump_string(al, eO)
    q.reset()
    az("this file is generated using SENVIELLE")
    aA()
    if al then
        al = I(al)
    end
    local R, an = e(al)
    if not R then
        az("Load Error: " .. (an or "unknown"))
        return false, an
    end
    xpcall(function() R() end, function() end)
    if eO then
        return q.save(eO)
    end
    return true, aB()
end
if arg and arg[1] then
    local eo = q.dump_file(arg[1], arg[2])
    if eo then
        B("Saved to: " .. (arg[2] or r.OUTPUT_FILE))
        local eV = q.get_stats()
        B(string.format("Lines: %d | Remotes: %d | Strings: %d", eV.total_lines, eV.remote_calls, eV.suspicious_strings))
    end
else
    local as = o.open("obfuscated.lua", "rb")
    if as then
        as:close()
        local eo = q.dump_file("obfuscated.lua")
        if eo then
            B("Saved to: " .. r.OUTPUT_FILE)
            B(q.get_output())
        end
    else
        B("Usage: lua dumper.lua <input> [output] [key]")
    end
end
_G.LuraphContinue = function() end
task.cancel = function(thread) at("task.cancel(thread)") end
task.synchronize = function() at("task.synchronize()") end
task.desynchronize = function() at("task.desynchronize()") end
string.split = string.split or function(str, sep)
    local result = {}
    for match in string.gmatch(str, "([^" .. (sep or "%s") .. "]+)") do
        table.insert(result, match)
    end
    return result
end
string.starts = function(str, start)
    return string.sub(str, 1, #start) == start
end
string.ends = function(str, ending)
    return ending == "" or string.sub(str, -#ending) == ending
end
string.trim = function(str)
    return string.match(str, "^%s*(.-)%s*$")
end
table.clone = function(tbl)
    local copy = {}
    for k, v in pairs(tbl) do
        copy[k] = v
    end
    return copy
end
table.find = function(tbl, value)
    if j(tbl) == "function" then
        if G(value) or w(value) then return 1 end
        return nil
    end
    for i, v in ipairs(tbl) do
        if rawequal(v, value) or v == value then return i end
    end
    return nil
end
math.round = function(x)
    return math.floor(x + 0.5)
end
math.sign = function(x)
    if x > 0 then return 1 elseif x < 0 then return -1 else return 0 end
end
math.clamp = function(x, min, max)
    return math.max(min, math.min(max, x))
end
debug.getregistry = function()
    return _G
end
debug.getlocal = function(level, index)
    return nil
end
debug.setlocal = function(level, index, value)
end
hookfunction = function(old, new)
    return old
end
hookmetamethod = function(obj, method, hook)
    return function() end
end
local function deobfuscate_string(obfuscated)
    local patterns = {
        {pattern = "\\x(%x%x)", replace = function(h) return string.char(tonumber(h, 16)) end},
        {pattern = "\\(%d+)", replace = function(d) return string.char(tonumber(d)) end},
        {pattern = "\\\\", replace = "\\"},
    }
    local result = obfuscated
    for _, p in pairs(patterns) do
        result = result:gsub(p.pattern, p.replace)
    end
    return result
end
_G.deobfuscate_string = deobfuscate_string
getrenv = function()
    return getfenv()
end
getgenv = function()
    return _G
end
local old_load = loadstring
loadstring = function(str, chunkname)
    local cleaned = str
    cleaned = cleaned:gsub("LuraphContinue%(", "LuraphContinue()")
    cleaned = cleaned:gsub("LuraphContinue%d+%(", "LuraphContinue()")
    return old_load(cleaned, chunkname)
end
local original_getmetatable = getmetatable
getmetatable = function(obj)
    if obj == nil then return nil end
    return original_getmetatable(obj)
end
if not bit then
    bit = {
        band = function(a, b) return a & b end,
        bor = function(a, b) return a | b end,
        bxor = function(a, b) return a ~ b end,
        bnot = function(a) return ~a & 0xFFFFFFFF end,
        lshift = function(a, n) return (a * 2^n) & 0xFFFFFFFF end,
        rshift = function(a, n) return math.floor(a / 2^n) & 0xFFFFFFFF end,
    }
end
function safe_string(str)
    if not str then return "nil" end
    if #str > 500 then
        return string.format('"%s..."', str:sub(1, 500):gsub('"', '\\"'))
    end
    return string.format("%q", str):gsub("\\\n", "\\n")
end
original_error = error
function error(msg, level)
    if type(msg) == "string" and msg:match("TIMEOUT") then
        print("[Deobfuscator] Timeout detected, continuing...")
        return
    end
    original_error(msg, level)
end
function all_pairs(t)
    return pairs(t or {})
end
function safe_pairs(t)
    if type(t) ~= "table" then return function() end end
    return pairs(t)
end
if not rawget(Enum, "MembershipType") then
    rawset(Enum, "MembershipType", bj("Enum.MembershipType", false))
end
local membership_items = {
    {Name = "None", Value = 0},
    {Name = "Premium", Value = 4},
}
for _, item in ipairs(membership_items) do
    local obj = bj("Enum.MembershipType." .. item.Name, false)
    t.registry[obj] = "Enum.MembershipType." .. item.Name
    if not t.property_store[obj] then t.property_store[obj] = {} end
    t.property_store[obj].Name = item.Name
    t.property_store[obj].Value = item.Value
    rawget(Enum, "MembershipType")[item.Name] = obj
end
local mps = game:GetService("MarketplaceService")
if mps and not mps.PromptPremiumPurchase then
    mps.PromptPremiumPurchase = function(self, player)
        return true
    end
end
if not rawget(Enum, "MembershipType") then
    rawset(Enum, "MembershipType", bj("Enum.MembershipType", false))
    local membership_items = {
        {Name = "None", Value = 0},
        {Name = "Premium", Value = 4},
    }
    for _, item in ipairs(membership_items) do
        local obj = bj("Enum.MembershipType." .. item.Name, false)
        t.registry[obj] = "Enum.MembershipType." .. item.Name
        if not t.property_store[obj] then t.property_store[obj] = {} end
        t.property_store[obj].Name = item.Name
        t.property_store[obj].Value = item.Value
        rawget(Enum, "MembershipType")[item.Name] = obj
    end
end
local function add_membership_type_to_player(proxy)
    if proxy and not t.property_store[proxy] then
        t.property_store[proxy] = {}
    end
    if proxy then
        t.property_store[proxy].MembershipType = rawget(Enum, "MembershipType").None
    end
end
local original_LocalPlayer = game:GetService("Players").LocalPlayer
if original_LocalPlayer then
    add_membership_type_to_player(original_LocalPlayer)
end
if not rawget(Enum, "ActionType") then
    rawset(Enum, "ActionType", bj("Enum.ActionType", false))
end
local action_type_items = {
    {Name = "Draw", Value = 1},
    {Name = "Win", Value = 2},
    {Name = "Drag", Value = 3},
    {Name = "Click", Value = 4},
}
for _, item in ipairs(action_type_items) do
    local obj = bj("Enum.ActionType." .. item.Name, false)
    t.registry[obj] = "Enum.ActionType." .. item.Name
    if not t.property_store[obj] then
        t.property_store[obj] = {}
    end
    t.property_store[obj].Name = item.Name
    t.property_store[obj].Value = item.Value
    rawget(Enum, "ActionType")[item.Name] = obj
end
if not rawget(_G, "DateTime") then
    rawset(_G, "DateTime", {
        fromUnixTimestamp = function(timestamp)
            return {
                FormatUniversalTime = function(self, format, locale) return "1970-01-01" end,
                FormatLocalTime = function(self, format, locale) return "1970-01-01" end,
                ToIsoDate = function(self) return "1970-01-01" end,
                UnixTimestamp = 0, UnixTimestampMillis = 0, Year = 1970, Month = 1, Day = 1,
                Hour = 0, Minute = 0, Second = 0
            }
        end,
        fromUnixTimestampMillis = function(timestamp)
            return _G.DateTime.fromUnixTimestamp(timestamp // 1000)
        end,
        fromIsoDate = function(isoDate)
            return _G.DateTime.fromUnixTimestamp(0)
        end,
        now = function()
            return _G.DateTime.fromUnixTimestamp(os.time())
        end
    })
end
if not string.split then
    string.split = function(str, sep)
        local result = {}
        for match in string.gmatch(str, "([^" .. (sep or "%s") .. "]+)") do
            table.insert(result, match)
        end
        return result
    end
end
local original_workspace = workspace
local workspace_mt = getmetatable(workspace) or {}
workspace_mt.BulkMoveTo = function(self, parts, cframes, bulkMoveMode)
    if type(parts) == "table" and type(cframes) == "table" then
        for i, part in ipairs(parts) do
            if i <= #cframes and part then
                if not t.property_store[part] then
                    t.property_store[part] = {}
                end
                t.property_store[part].CFrame = cframes[i]
                part.CFrame = cframes[i]
            end
        end
    end
    return true
end
setmetatable(original_workspace, workspace_mt)
local original_bulk_move_mode = Enum.BulkMoveMode
if not original_bulk_move_mode then
    rawset(Enum, "BulkMoveMode", bj("Enum.BulkMoveMode", false))
    local bulk_move_items = {
        {Name = "FireCFrameChanged", Value = 0},
        {Name = "FireAll", Value = 1},
    }
    for _, item in ipairs(bulk_move_items) do
        local obj = bj("Enum.BulkMoveMode." .. item.Name, false)
        t.registry[obj] = "Enum.BulkMoveMode." .. item.Name
        if not t.property_store[obj] then t.property_store[obj] = {} end
        t.property_store[obj].Name = item.Name
        t.property_store[obj].Value = item.Value
        rawget(Enum, "BulkMoveMode")[item.Name] = obj
    end
end
local original_bj = bj
function bj(...)
    local proxy = original_bj(...)
    if proxy and t.registry[proxy] and t.registry[proxy]:match("Folder") then
        if not t.property_store[proxy] then
            t.property_store[proxy] = {}
        end
        if not t.property_store[proxy].Children then
            t.property_store[proxy].Children = {}
        end
        local mt = getmetatable(proxy)
        local old_index = mt.__index
        mt.__index = function(self, key)
            if key == "GetChildren" then
                return function(self)
                    return t.property_store[self].Children or {}
                end
            end
            if key == "ChildAdded" or key == "ChildRemoved" then
                return bj("RBXScriptSignal", false)
            end
            if old_index then
                return old_index(self, key)
            end
            return nil
        end
    end
    return proxy
end
local log_service = game:GetService("LogService")
if not log_service then
    local LogService = bj("LogService", false)
    rawset(game, "LogService", LogService)
    t.property_store[LogService] = {}
    log_service = LogService
end
if not log_service.GetLogHistory then
    log_service.GetLogHistory = function(self)
        return {}
    end
end
if not log_service.MessageOut then
    local message_out_signal = bj("RBXScriptSignal", false)
    t.registry[message_out_signal] = "LogService.MessageOut"
    rawset(log_service, "MessageOut", message_out_signal)
end
if not _G.LogService then
    _G.LogService = log_service
end
if not rawget(_G, "RBXScriptSignal") then
    _G.RBXScriptSignal = {
        Connect = function(self, callback) return {Disconnect = function() end} end,
        Wait = function(self) return end,
        Once = function(self, callback) return {Disconnect = function() end} end
    }
end
local PolicyService = bj("PolicyService", true)
t.property_store[PolicyService] = t.property_store[PolicyService] or {}
local policy_mt = getmetatable(PolicyService) or {}

policy_mt.GetPolicyForPlayer = function(self, player)
    at(string.format("%s:GetPolicyForPlayer(%s)", t.registry[self] or "PolicyService", aZ(player)))
    local policy = bj("Policy", false)
    aW(policy, "policy")
    t.property_store[policy] = {Name = "DefaultPolicy", Version = 1, Rules = {}}
    return policy
end

policy_mt.GetPolicies = function(self)
    at(string.format("%s:GetPolicies()", t.registry[self] or "PolicyService"))
    return {}
end

policy_mt.GetPolicyById = function(self, policyId)
    at(string.format("%s:GetPolicyById(%s)", t.registry[self] or "PolicyService", aZ(policyId)))
    local policy = bj("Policy", false)
    aW(policy, "policy")
    return policy
end

policy_mt.GetCurrentPolicy = function(self)
    at(string.format("%s:GetCurrentPolicy()", t.registry[self] or "PolicyService"))
    local policy = bj("Policy", false)
    aW(policy, "currentPolicy")
    return policy
end

policy_mt.GetPolicyForUser = function(self, userId)
    at(string.format("%s:GetPolicyForUser(%s)", t.registry[self] or "PolicyService", aZ(userId)))
    local policy = bj("Policy", false)
    aW(policy, "userPolicy")
    return policy
end

policy_mt.IsSubjectToPolicy = function(self, player, policyName)
    at(string.format("%s:IsSubjectToPolicy(%s, %s)", t.registry[self] or "PolicyService", aZ(player), aH(policyName)))
    return true
end

policy_mt.GetPolicyViolations = function(self, player)
    at(string.format("%s:GetPolicyViolations(%s)", t.registry[self] or "PolicyService", aZ(player)))
    return {}
end

policy_mt.GetAllowedContent = function(self, contentType, policyId)
    at(string.format("%s:GetAllowedContent(%s, %s)", t.registry[self] or "PolicyService", aZ(contentType), aZ(policyId)))
    return {}
end

policy_mt.IsContentAllowed = function(self, contentId, contentType, player)
    at(string.format("%s:IsContentAllowed(%s, %s, %s)", t.registry[self] or "PolicyService", aZ(contentId), aZ(contentType), aZ(player)))
    return true
end

policy_mt.GetRestrictedFeatures = function(self, player)
    at(string.format("%s:GetRestrictedFeatures(%s)", t.registry[self] or "PolicyService", aZ(player)))
    return {}
end

policy_mt.IsFeatureRestricted = function(self, feature, player)
    at(string.format("%s:IsFeatureRestricted(%s, %s)", t.registry[self] or "PolicyService", aZ(feature), aZ(player)))
    return false
end

setmetatable(PolicyService, policy_mt)

if not game:FindFirstChild("PolicyService") then
    rawset(game, "PolicyService", PolicyService)
end
_G.PolicyService = PolicyService
local old_bj = bj
local function create_real_value_proxy(value, type_name)
    local proxy = {}
    local mt = {}
    if type_name == "number" then
        mt.__tostring = function() return tostring(value) end
        mt.__add = function(a, b) return create_real_value_proxy((rawget(a, "__v") or value) + (type(b) == "table" and rawget(b, "__v") or b), "number") end
        mt.__sub = function(a, b) return create_real_value_proxy((rawget(a, "__v") or value) - (type(b) == "table" and rawget(b, "__v") or b), "number") end
        mt.__mul = function(a, b) return create_real_value_proxy((rawget(a, "__v") or value) * (type(b) == "table" and rawget(b, "__v") or b), "number") end
        mt.__div = function(a, b) return create_real_value_proxy((rawget(a, "__v") or value) / (type(b) == "table" and rawget(b, "__v") or b), "number") end
        mt.__pow = function(a, b) return create_real_value_proxy((rawget(a, "__v") or value) ^ (type(b) == "table" and rawget(b, "__v") or b), "number") end
        mt.__unm = function(a) return create_real_value_proxy(-(rawget(a, "__v") or value), "number") end
        mt.__eq = function(a, b) return (rawget(a, "__v") or value) == (type(b) == "table" and rawget(b, "__v") or b) end
        mt.__lt = function(a, b) return (rawget(a, "__v") or value) < (type(b) == "table" and rawget(b, "__v") or b) end
        mt.__le = function(a, b) return (rawget(a, "__v") or value) <= (type(b) == "table" and rawget(b, "__v") or b) end
    elseif type_name == "string" then
        mt.__tostring = function() return value end
        mt.__len = function() return #value end
        mt.__concat = function(a, b)
            local av = rawget(a, "__v") or value
            local bv = type(b) == "table" and rawget(b, "__v") or b
            return create_real_value_proxy(av .. tostring(bv), "string")
        end
        mt.__eq = function(a, b)
            local av = rawget(a, "__v") or value
            local bv = type(b) == "table" and rawget(b, "__v") or b
            return av == bv
        end
    elseif type_name == "boolean" then
        mt.__tostring = function() return tostring(value) end
        mt.__eq = function(a, b)
            local av = rawget(a, "__v") or value
            local bv = type(b) == "table" and rawget(b, "__v") or b
            return av == bv
        end
    end
    rawset(proxy, "__v", value)
    rawset(proxy, "__t", type_name)
    mt.__index = function(self, key)
        if key == "__v" or key == "__t" then return rawget(self, key) end
        if type_name == "string" then
            local str = rawget(self, "__v")
            if string[key] then
                return function(self, ...)
                    local args = {...}
                    for i, arg in ipairs(args) do
                        if type(arg) == "table" and rawget(arg, "__v") then
                            args[i] = rawget(arg, "__v")
                        end
                    end
                    local result = string[key](str, table.unpack(args))
                    if type(result) == "string" then
                        return create_real_value_proxy(result, "string")
                    end
                    if type(result) == "number" then
                        return create_real_value_proxy(result, "number")
                    end
                    return result
                end
            end
        end
        if type_name == "number" and math[key] then
            return function(self, ...)
                local args = {...}
                for i, arg in ipairs(args) do
                    if type(arg) == "table" and rawget(arg, "__v") then
                        args[i] = rawget(arg, "__v")
                    end
                end
                local result = math[key](rawget(self, "__v"), table.unpack(args))
                if type(result) == "number" then
                    return create_real_value_proxy(result, "number")
                end
                return result
            end
        end
        return nil
    end
    mt.__newindex = function() end
    mt.__pairs = function() return function() return nil end end
    mt.__ipairs = mt.__pairs
    setmetatable(proxy, mt)
    t.registry[proxy] = value
    t.variable_types[proxy] = type_name
    return proxy
end
local function is_proxy_with_value(x)
    if type(x) == "table" and rawget(x, "__v") ~= nil then
        return true, rawget(x, "__v"), rawget(x, "__t")
    end
    return false, nil, nil
end
local original_type = type
_G.type = function(x)
    local is_proxy, val, tname = is_proxy_with_value(x)
    if is_proxy then
        return tname
    end
    if G(x) then
        local reg = t.registry[x]
        if reg and type(reg) == "string" then
            if reg:match('^"') or reg:match("^'") or reg:match('^%[') then
                return "string"
            end
            if tonumber(reg) ~= nil then
                return "number"
            end
            if reg == "true" or reg == "false" then
                return "boolean"
            end
        end
        return "userdata"
    end
    return original_type(x)
end
local original_tonumber = tonumber
_G.tonumber = function(x, base)
    local is_proxy, val = is_proxy_with_value(x)
    if is_proxy and type(val) == "number" then
        return val
    end
    if is_proxy and type(val) == "string" then
        return original_tonumber(val, base)
    end
    return original_tonumber(x, base)
end
local original_tostring = tostring
_G.tostring = function(x)
    local is_proxy, val = is_proxy_with_value(x)
    if is_proxy then
        return tostring(val)
    end
    if G(x) then
        local reg = t.registry[x]
        if reg then
            if type(reg) == "string" and (reg:match('^"') or reg:match("^'")) then
                local str = reg:sub(2, -2)
                return str
            end
            return reg
        end
        return "Instance"
    end
    return original_tostring(x)
end
local original_getmetatable = getmetatable
_G.getmetatable = function(x)
    local is_proxy = is_proxy_with_value(x)
    if is_proxy then
        local mt = original_getmetatable(x)
        if mt then return mt end
        return nil
    end
    if G(x) then
        return nil
    end
    return original_getmetatable(x)
end
local old_bj_original = bj
bj = function(name, is_global, parent)
    if type(name) == "string" and (name:match('^"') or name:match("^'")) then
        local str_value = name:sub(2, -2)
        return create_real_value_proxy(str_value, "string")
    end
    if type(name) == "number" or (type(name) == "string" and tonumber(name) ~= nil) then
        local num_value = tonumber(name)
        return create_real_value_proxy(num_value, "number")
    end
    if name == "true" then
        return create_real_value_proxy(true, "boolean")
    end
    if name == "false" then
        return create_real_value_proxy(false, "boolean")
    end
    return old_bj_original(name, is_global, parent)
end
local function fix_proxy_value_behavior(proxy, original_value, value_type)
    if not proxy then return end
    if value_type == "number" then
        t.registry[proxy] = original_value
    elseif value_type == "string" then
        t.registry[proxy] = original_value
    elseif value_type == "boolean" then
        t.registry[proxy] = original_value
    end
    t.variable_types[proxy] = value_type
end
local original_aW = aW
aW = function(x, name, var_type, source)
    if var_type == "number" or var_type == "string" or var_type == "boolean" then
        local id = "Var" .. (t.lar_counter + 1)
        t.lar_counter = t.lar_counter + 1
        t.registry[x] = id
        t.reverse_registry[id] = x
        t.variable_types[x] = var_type
        if var_type == "number" and type(name) == "number" then
            rawset(x, "__v", name)
        end
        if var_type == "string" and type(name) == "string" then
            rawset(x, "__v", name)
        end
        if var_type == "boolean" then
            rawset(x, "__v", name == "true" or name == true)
        end
        return id
    end
    return original_aW(x, name, var_type, source)
end
Vector3 = function(x, y, z)
    local proxy = old_bj_original("Vector3", false)
    local mt = getmetatable(proxy)
    local real_value = {X = x or 0, Y = y or 0, Z = z or 0}
    real_value.Magnitude = math.sqrt(real_value.X^2 + real_value.Y^2 + real_value.Z^2)
    t.property_store[proxy] = real_value
    if not mt.__index then
        mt.__index = function(self, key)
            if key == "X" then return t.property_store[self].X end
            if key == "Y" then return t.property_store[self].Y end
            if key == "Z" then return t.property_store[self].Z end
            if key == "Magnitude" then return t.property_store[self].Magnitude end
            if key == "Dot" then
                return function(self, other)
                    local v1 = self
                    local v2 = other
                    return v1.X * v2.X + v1.Y * v2.Y + v1.Z * v2.Z
                end
            end
            if key == "Cross" then
                return function(self, other)
                    local v1 = self
                    local v2 = other
                    return Vector3(
                        v1.Y * v2.Z - v1.Z * v2.Y,
                        v1.Z * v2.X - v1.X * v2.Z,
                        v1.X * v2.Y - v1.Y * v2.X
                    )
                end
            end
            return nil
        end
    end
    if not mt.__newindex then
        mt.__newindex = function(self, key, value)
            if key == "X" then
                t.property_store[self].X = value
                t.property_store[self].Magnitude = math.sqrt(t.property_store[self].X^2 + t.property_store[self].Y^2 + t.property_store[self].Z^2)
            elseif key == "Y" then
                t.property_store[self].Y = value
                t.property_store[self].Magnitude = math.sqrt(t.property_store[self].X^2 + t.property_store[self].Y^2 + t.property_store[self].Z^2)
            elseif key == "Z" then
                t.property_store[self].Z = value
                t.property_store[self].Magnitude = math.sqrt(t.property_store[self].X^2 + t.property_store[self].Y^2 + t.property_store[self].Z^2)
            end
        end
    end
    return proxy
end
local original_typeof = typeof
_G.typeof = function(x)
    local is_proxy, val, tname = is_proxy_with_value(x)
    if is_proxy then
        if tname == "number" then return "number" end
        if tname == "string" then return "string" end
        if tname == "boolean" then return "boolean" end
    end
    if G(x) and t.property_store[x] and t.property_store[x].X ~= nil then
        return "Vector3"
    end
    if G(x) then
        local reg = t.registry[x]
        if reg then
            local match = reg:match("^(%a+)")
            if match and (match == "Vector3" or match == "Vector2" or match == "CFrame" or match == "Ray" or match == "Color3" or match == "BrickColor" or match == "UDim2" or match == "UDim" or match == "TweenInfo" or match == "Rect" or match == "Region3") then
                return match
            end
        end
    end
    return original_typeof(x)
end
local real_utf8 = utf8 or {}
if not real_utf8.len then
    real_utf8.len = function(s)
        if type(s) == "string" then
            local _, count = string.gsub(s, "[%z\1-\127\194-\244][\128-\191]*", "")
            return count
        end
        local is_proxy, val, tname = is_proxy_with_value(s)
        if is_proxy and tname == "string" then
            local _, count = string.gsub(val, "[%z\1-\127\194-\244][\128-\191]*", "")
            return count
        end
        return nil
    end
end
utf8 = real_utf8
_G.utf8 = utf8
local real_string_mt = getmetatable("") or {}
if not real_string_mt.__len then
    real_string_mt.__len = function(s)
        if type(s) == "string" then return #s end
        local is_proxy, val = is_proxy_with_value(s)
        if is_proxy and type(val) == "string" then
            return #val
        end
        return 0
    end
    setmetatable("", real_string_mt)
end
return q -- akhirannya di sini:3
