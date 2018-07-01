package net.logicaltrust.tab;

import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.HeadlessException;
import java.awt.Toolkit;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.UnsupportedFlavorException;
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
	private ResponseTextEditor responseTextEditor;
	int previousRow = -1;

	public MockTable(String title, String tooltip, MockRepository mockHolder, 
			Consumer<Collection<String>> updateValues, SimpleLogger logger, ResponseTextEditor responseTextEditor) {
		
		this.responseTextEditor = responseTextEditor;
		this.setBorder(new TitledBorder(new LineBorder(new Color(0, 0, 0)), title, TitledBorder.LEADING, TitledBorder.TOP, null, null));
		this.setToolTipText(tooltip);
		this.setLayout(new BorderLayout(0, 0));
		
		model = new MockTableModel(mockHolder, logger);
		
		JPanel buttonPanel = createButtonPanel();
		JTable table = createTable();

		JButton addButton = new JButton("Add");
		addButton.addActionListener(e -> handleAdd());
		
		JButton deleteButton = new JButton("Delete");
		deleteButton.addActionListener(e -> handleDelete(table) );
		
		JButton pasteUrlButton = new JButton("Paste URL");
		pasteUrlButton.addActionListener(e -> handlePasteURL(logger));

		buttonPanel.add(addButton, createTableButtonConstraints(0));
		buttonPanel.add(deleteButton, createTableButtonConstraints(1));
		buttonPanel.add(pasteUrlButton, createTableButtonConstraints(2));
		
		ListSelectionModel selectionModel = table.getSelectionModel();
		selectionModel.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		selectionModel.addListSelectionListener(e -> handleTableSelection(mockHolder, logger, responseTextEditor, table));
	}

	private void handleTableSelection(MockRepository mockHolder, SimpleLogger logger,
			ResponseTextEditor responseTextEditor, JTable table) {
		int row = table.getSelectedRow();
		logger.debug("Selection changed, from: " + previousRow + " to: " + row);
		if (row != previousRow) {
			boolean cancel = false;
			if (responseTextEditor.hasUnsavedChanges()) {
				int result = JOptionPane.showConfirmDialog(null, "Do you want to save before leave?", "Changes not saved", JOptionPane.YES_NO_CANCEL_OPTION);
				if (result == JOptionPane.YES_OPTION) {
					responseTextEditor.saveChanges();
					previousRow = row;
				} else if (result == JOptionPane.NO_OPTION) {
					//discard
					previousRow = row;
				} else {
					//go back
					table.setRowSelectionInterval(previousRow, previousRow);
					cancel = true;
				}
			}
			
			if (!cancel) {
				previousRow = row;
				MockEntry entry = mockHolder.getEntry(row);
				logger.debug("Selected row: " + row + ", entry: " + entry.getId() + ", " + entry.getRule());
				responseTextEditor.loadResponse(entry);
			}
		}
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
		int result = JOptionPane.showConfirmDialog(null, msg, "Add mock", JOptionPane.OK_CANCEL_OPTION);
		if (result == JOptionPane.OK_OPTION) {
			MockRule rule = new MockRule((MockProtocolEnum) proto.getSelectedItem(), host.getText(), port.getText(), file.getText());
			addRule(rule);
		}
	}

	private void handleDelete(JTable table) {
		int selectedRow = table.getSelectedRow();
		if (selectedRow != -1) {
			model.removeRow(selectedRow);
		}
	}

	private void handlePasteURL(SimpleLogger logger) {
		try {
			String clipboard = (String) Toolkit.getDefaultToolkit().getSystemClipboard().getData(DataFlavor.stringFlavor);
			try {
				URL url = new URL(clipboard);
				MockRule rule = new MockRule(url);
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
		JTable table = new JTable();
		table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		table.setModel(model);
		table.getColumnModel().getColumn(0).setMaxWidth(55);
		table.getColumnModel().getColumn(1).setMaxWidth(75);
		table.getColumnModel().getColumn(1).setPreferredWidth(70);
		table.getColumnModel().getColumn(2).setPreferredWidth(150);
		table.getColumnModel().getColumn(3).setMaxWidth(70);
		table.getColumnModel().getColumn(3).setPreferredWidth(65);
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
		buttonPanelLayout.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
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
