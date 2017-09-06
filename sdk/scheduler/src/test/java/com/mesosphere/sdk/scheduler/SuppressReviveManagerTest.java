package com.mesosphere.sdk.scheduler;

/**
 * This class tests {@link ReviveManager}.
 */
public class SuppressReviveManagerTest {
    /*
    private StateStore stateStore;

    // This EventBus publishes events synchronously.  Changing this property would invalidate assertions in tests below.
    // For example, asserting that a state transition does not occur after an event is safe now, that assertion would
    // prove nothing if we put an asynchronous EventBus here.
    private EventBus eventBus = new EventBus();
    private ReviveManager suppressReviveManager;

    @Mock private SchedulerDriver driver;
    @Mock private PlanManager planManager;

    @Mock private Plan completePlan;
    @Mock private Plan inprogressPlan;

    @Mock private Phase completePhase;
    @Mock private Phase inProgressPhase;

    @Mock private ConfigStore<ServiceSpec> configStore;

    @Before
    public void beforeEach() {
        stateStore = new StateStore(new MemPersister());
        suppressReviveManager = null;

        MockitoAnnotations.initMocks(this);

        when(completePhase.getStatus()).thenReturn(Status.COMPLETE);
        when(inProgressPhase.getStatus()).thenReturn(Status.IN_PROGRESS);

        when(completePlan.getName()).thenReturn("complete-plan");
        when(completePlan.getChildren()).thenReturn(Arrays.asList(completePhase));

        when(inprogressPlan.getName()).thenReturn("in-progress-plan");
        when(inprogressPlan.getChildren()).thenReturn(Arrays.asList(inProgressPhase));
    }

    @Test
    public void startWithCompletePlan() {
        when(planManager.getPlan()).thenReturn(completePlan);
        suppressReviveManager = new ReviveManager(
                stateStore,
                configStore,
                driver,
                eventBus,
                Arrays.asList(planManager));
        suppressReviveManager.start();
        waitState(suppressReviveManager, ReviveManager.State.WAITING_FOR_OFFER);
    }

    @Test
    public void startWithInProgressPlan() {
        when(planManager.getPlan()).thenReturn(inprogressPlan);
        suppressReviveManager = new ReviveManager(
                stateStore,
                configStore,
                driver,
                eventBus,
                Arrays.asList(planManager));
        suppressReviveManager.start();
        waitState(suppressReviveManager, ReviveManager.State.WAITING_FOR_OFFER);
    }

    @Test
    public void suppressWhenComplete() {
        getSuppressedManager();
    }

    @Test
    public void reviveOnTaskFailure() {
        suppressReviveManager = getSuppressedManager();
        sendFailedTaskStatus();
        Assert.assertEquals(ReviveManager.State.WAITING_FOR_OFFER, suppressReviveManager.getState());
        sendOffer();
        Assert.assertEquals(ReviveManager.State.REVIVED, suppressReviveManager.getState());

        // Should go back to suppressed because all plans remain complete
        waitSuppressed(stateStore, suppressReviveManager);
    }

    @Test
    public void reviveOnPlanInProgress() {
        suppressReviveManager = getSuppressedManager();
        when(planManager.getPlan()).thenReturn(inprogressPlan);
        waitState(suppressReviveManager, ReviveManager.State.WAITING_FOR_OFFER);
        waitStateStore(stateStore, false);
        sendOffer();
        waitRevived(stateStore, suppressReviveManager);
    }

    @Test
    public void avoidRevivingFromRevivedState() {
        reviveOnPlanInProgress();
        sendFailedTaskStatus();
        Assert.assertEquals(ReviveManager.State.REVIVED, suppressReviveManager.getState());
    }

    @Test
    public void reviveOnTasksNeedingRecovery() {
        when(planManager.getPlan()).thenReturn(completePlan);
        TestSuppressReviveManager testSuppressReviveManager = new TestSuppressReviveManager(
                stateStore,
                configStore,
                driver,
                eventBus,
                Arrays.asList(planManager),
                0,
                1);
        testSuppressReviveManager.start();
        waitState(testSuppressReviveManager, ReviveManager.State.WAITING_FOR_OFFER);
        sendOffer();
        waitSuppressed(stateStore, testSuppressReviveManager);
        testSuppressReviveManager.setTasksNeedRecovery(true);
        waitState(testSuppressReviveManager, ReviveManager.State.WAITING_FOR_OFFER);
    }

    private static class TestSuppressReviveManager extends ReviveManager {
        private boolean tasksNeedRecovery = false;

        public TestSuppressReviveManager(
                StateStore stateStore,
                ConfigStore<ServiceSpec> configStore,
                SchedulerDriver driver,
                EventBus eventBus,
                Collection<PlanManager> planManagers,
                int pollDelay,
                int pollInterval) {
            super(stateStore, configStore, driver, eventBus, planManagers, pollDelay, pollInterval);
        }

        @Override
        protected boolean hasTasksNeedingRecovery() {
            return tasksNeedRecovery;
        }

        public void setTasksNeedRecovery(boolean tasksNeedRecovery) {
            this.tasksNeedRecovery =  tasksNeedRecovery;
        }
    }

    private ReviveManager getSuppressedManager() {
        when(planManager.getPlan()).thenReturn(completePlan);
        Assert.assertFalse(StateStoreUtils.isSuppressed(stateStore));
        ReviveManager suppressReviveManager = getSuppressReviveManager(planManager);
        suppressReviveManager.start();
        waitState(suppressReviveManager, ReviveManager.State.WAITING_FOR_OFFER);
        sendOffer();
        waitSuppressed(stateStore, suppressReviveManager);
        return suppressReviveManager;
    }

    private ReviveManager getSuppressReviveManager(PlanManager planManager) {
        return new ReviveManager(
                stateStore,
                configStore,
                driver,
                eventBus,
                Arrays.asList(planManager),
                0,
                1);
    }

    private static void waitState(ReviveManager suppressReviveManager, ReviveManager.State state) {
        Awaitility.await()
                .atMost(5, TimeUnit.SECONDS)
                .until(new Callable<Boolean>() {
                    @Override
                    public Boolean call() throws Exception {
                        return suppressReviveManager.getState().equals(state);
                    }
                });
    }

    private static void waitSuppressed(StateStore stateStore, ReviveManager suppressReviveManager) {
        waitStateStore(stateStore, true);
        waitState(suppressReviveManager, ReviveManager.State.SUPPRESSED);
    }

    private static void waitRevived(StateStore stateStore, ReviveManager suppressReviveManager) {
        waitStateStore(stateStore, false);
        waitState(suppressReviveManager, ReviveManager.State.REVIVED);
    }

    private static void waitStateStore(StateStore stateStore, boolean suppressed) {
        Awaitility.await()
                .atMost(5, TimeUnit.SECONDS)
                .until(new Callable<Boolean>() {
                    @Override
                    public Boolean call() throws Exception {
                        return StateStoreUtils.isSuppressed(stateStore) == suppressed;
                    }
                });
    }

    private void sendOffer() {
        Protos.Offer offer = Protos.Offer.newBuilder()
                .setId(TestConstants.OFFER_ID)
                .setFrameworkId(TestConstants.FRAMEWORK_ID)
                .setSlaveId(TestConstants.AGENT_ID)
                .setHostname(TestConstants.HOSTNAME)
                .build();

        eventBus.post(offer);
    }

    private void sendFailedTaskStatus() {
        sendTaskStatus(Protos.TaskState.TASK_FAILED);
    }

    private void sendTaskStatus(Protos.TaskState state) {
        Protos.TaskStatus taskStatus = Protos.TaskStatus.newBuilder()
                .setTaskId(TestConstants.TASK_ID)
                .setState(state)
                .build();

        eventBus.post(taskStatus);
    }
    */
}
