package net.logicaltrust.tab;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.HeadlessException;
import java.awt.Toolkit;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.UnsupportedFlavorException;
import java.awt.event.MouseEvent;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Collection;
import java.util.function.Consumer;

import javax.swing.DefaultCellEditor;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.border.LineBorder;
import javax.swing.border.TitledBorder;

import net.logicaltrust.SimpleLogger;
import net.logicaltrust.editor.ResponseTextEditor;
import net.logicaltrust.model.MockEntry;
import net.logicaltrust.model.MockProtocolEnum;
import net.logicaltrust.model.MockRule;
import net.logicaltrust.persistent.MockRepository;

public class MockTable extends JPanel {

	private static final long serialVersionUID = 1L;
	private MockTableModel model;
	int previousRow = -1;
	private SimpleLogger logger;
	private ResponseTextEditor responseTextEditor;
	private JTable table;
	private MockRepository mockHolder;

	public MockTable(String title, String tooltip, MockRepository mockHolder, 
			Consumer<Collection<String>> updateValues, SimpleLogger logger, ResponseTextEditor responseTextEditor) {
		this.mockHolder = mockHolder;
		this.logger = logger;
		this.responseTextEditor = responseTextEditor;
		this.setBorder(new TitledBorder(new LineBorder(new Color(0, 0, 0)), title, TitledBorder.LEADING, TitledBorder.TOP, null, null));
		this.setToolTipText(tooltip);
		this.setLayout(new BorderLayout(0, 0));
		model = new MockTableModel(mockHolder, logger);
		
		JPanel buttonPanel = createButtonPanel();
		table = createTable();

		JButton addButton = new JButton("Add");
		addButton.addActionListener(e -> handleAdd());
		JButton deleteButton = new JButton("Delete");
		deleteButton.addActionListener(e -> handleDelete() );
		JButton pasteUrlButton = new JButton("Paste URL");
		pasteUrlButton.addActionListener(e -> handlePasteURL());
		JButton duplicateButton = new JButton("Duplicate");
		duplicateButton.addActionListener(e -> handleDuplicate());
		JButton upButton = new JButton("Up");
		upButton.addActionListener(e -> handleUp());
		JButton downButton = new JButton("Down");
		downButton.addActionListener(e -> handleDown());
		

		buttonPanel.add(addButton, createTableButtonConstraints(0));
		buttonPanel.add(deleteButton, createTableButtonConstraints(1));
		buttonPanel.add(pasteUrlButton, createTableButtonConstraints(2));
		buttonPanel.add(duplicateButton, createTableButtonConstraints(3));
		buttonPanel.add(upButton, createTableButtonConstraints(4));
		buttonPanel.add(downButton, createTableButtonConstraints(5));
		
		ListSelectionModel selectionModel = table.getSelectionModel();
		selectionModel.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		selectionModel.addListSelectionListener(e -> handleTableSelection());
	}
	
	private void handleDuplicate() {
		int row = table.getSelectedRow();
		if (row != -1) {
			MockEntry entry = mockHolder.getEntryByIndex(row);
			MockEntry duplicate = entry.duplicate();
			model.addMock(duplicate);
		}
	}
	
	private void handleUp() {
		int selectedRow = table.getSelectedRow();
		if (selectedRow > 0) {
			moveRow(selectedRow, -1);
		}
	}
	
	private void handleDown() {
		int selectedRow = table.getSelectedRow();
		if (selectedRow < model.getRowCount() - 1) {
			moveRow(selectedRow, 1);
		}
	}
	
	private void moveRow(int row, int step) {
		int newRow = row + step;
		model.moveRow(row, row, newRow);
		previousRow = newRow;
		table.setRowSelectionInterval(newRow, newRow);
	}

	private void handleTableSelection() {
		int row = table.getSelectedRow();
		logger.debug("Selection changed, from: " + previousRow + " to: " + row);
		if (row != previousRow) {
			if (row == -1) {
				unloadEntry();
			} else {
				selectionChanged(row);
			}
		}
	}

	private void selectionChanged(int row) {
		if (responseTextEditor.hasUnsavedChanges()) {
			int result = JOptionPane.showConfirmDialog(this, "Do you want to save before leave?", "Changes not saved", JOptionPane.YES_NO_CANCEL_OPTION);
			if (result == JOptionPane.YES_OPTION) {
				responseTextEditor.saveChanges();
			} else if (result == JOptionPane.CANCEL_OPTION) {
				table.setRowSelectionInterval(previousRow, previousRow);
				return;
			}
		}
		goToNextEntry(row);
	}
	
	private void goToNextEntry(int row) {
		previousRow = row;
		MockEntry entry = mockHolder.getEntryByIndex(row);
		logger.debug("Selected row: " + row + ", entry: " + entry);
		responseTextEditor.loadResponse(entry);
	}
	
	private void unloadEntry() {
		previousRow = -1;
		logger.debug("Selected row: -1, no entry");
		responseTextEditor.unloadResponse();
	}

	private void prepareProtocolEnumCombo(JTable table) {
		JComboBox<MockProtocolEnum> protoCombo = new JComboBox<>(MockProtocolEnum.values());
		table.getColumnModel().getColumn(1).setCellEditor(new DefaultCellEditor(protoCombo));
	}

	private void handleAdd() {
		JComboBox<MockProtocolEnum> proto = new JComboBox<>(MockProtocolEnum.values());
		JTextField host = new JTextField();
		JTextField port = new JTextField();
		JTextField file = new JTextField();
		Object[] msg = new Object[] { "Protocol", proto, "Host", host, "Port", port, "File", file };
		int result = JOptionPane.showConfirmDialog(this, msg, "Add mock", JOptionPane.OK_CANCEL_OPTION);
		if (result == JOptionPane.OK_OPTION) {
			MockRule rule = new MockRule((MockProtocolEnum) proto.getSelectedItem(), host.getText(), port.getText(), file.getText());
			addRule(rule);
		}
	}

	private void handleDelete() {
		int selectedRow = table.getSelectedRow();
		if (selectedRow != -1) {
			model.removeRow(selectedRow);
		}
	}

	private void handlePasteURL() {
		try {
			String clipboard = (String) Toolkit.getDefaultToolkit().getSystemClipboard().getData(DataFlavor.stringFlavor);
			try {
				URL url = new URL(clipboard);
				MockRule rule = MockRule.fromURL(url);
				addRule(rule);
			} catch (MalformedURLException e2) {
				logger.debug("Cannot parse URL " + clipboard);
			}
		} catch (HeadlessException | UnsupportedFlavorException | IOException e1) {
			logger.debug("Cannot read clipboard");
			e1.printStackTrace(logger.getStderr());
		}
	}

	private JTable createTable() {
		JTable table = new JTable() {
			private static final long serialVersionUID = 1L;
			@Override
			public String getToolTipText(MouseEvent event) {
				int row = this.rowAtPoint(event.getPoint());
				int column = this.columnAtPoint(event.getPoint());
				Object value = model.getValueAt(row, column);
				return value + "";
			}	
		};
		table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		table.setModel(model);
		table.getColumnModel().getColumn(0).setMaxWidth(65);
		table.getColumnModel().getColumn(1).setMaxWidth(75);
		table.getColumnModel().getColumn(1).setPreferredWidth(70);
		table.getColumnModel().getColumn(2).setPreferredWidth(150);
		table.getColumnModel().getColumn(3).setMaxWidth(70);
		table.getColumnModel().getColumn(3).setPreferredWidth(70);
		table.getColumnModel().getColumn(4).setPreferredWidth(300);
		prepareProtocolEnumCombo(table);
		JScrollPane scroll = new JScrollPane(table);
		scroll.setVisible(true);
		this.add(scroll, BorderLayout.CENTER);
		return table;
	}

	private JPanel createButtonPanel() {
		JPanel buttonPanel = new JPanel();
		GridBagLayout buttonPanelLayout = new GridBagLayout();
		buttonPanelLayout.columnWidths = new int[] {50};
		buttonPanelLayout.rowHeights = new int[] {0, 0, 0, 25};
		buttonPanelLayout.columnWeights = new double[]{0.0};
		buttonPanelLayout.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
		buttonPanel.setLayout(buttonPanelLayout);
		this.add(buttonPanel, BorderLayout.WEST);
		return buttonPanel;
	}
	
	private void addRule(MockRule rule) {
		MockEntry entry = new MockEntry(true, rule, null);
		model.addMock(entry);
	}

	private GridBagConstraints createTableButtonConstraints(int index) {
		GridBagConstraints btnConstraints = new GridBagConstraints();
		btnConstraints.fill = GridBagConstraints.HORIZONTAL;
		btnConstraints.anchor = GridBagConstraints.NORTH;
		btnConstraints.gridx = 0;
		btnConstraints.gridy = index;
		return btnConstraints;
	}

	public void addMock(MockEntry entry) {
		model.addMock(entry);
	}

}
